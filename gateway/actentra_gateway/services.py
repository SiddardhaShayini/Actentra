"""Typed Application Services layer for Actentra.

Unifies core deterministic kernel, executors, persistent receipts, approvals,
canary simulations, and audit reporting for both the CLI and Local Web UI.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import math
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from actentra.boundary import ActionBlockedError, Boundary
from actentra_core.canonicalize import (
    CanonicalizationError,
    canonicalize_resource,
    canonicalize_unicode,
    canonicalize_windows_path,
    hash_canonical,
)
from actentra_core.causal import (
    CausalLink,
    build_causal_trace,
    generate_link_id,
)
from actentra_core.checkpoints import CheckpointAnchor, KeyRing
from actentra_core.claims import ExecutionClaimError
from actentra_core.context import (
    ContextError,
    PostconditionSpec,
    validate_postcondition_semantics,
)
from actentra_core.coordination import (
    LeaseMode,
    ResourceConflictError,
    build_lease,
    utc_iso,
)
from actentra_core.envelope import (
    ActionEnvelope,
    EnvelopeError,
    ProvenanceItem,
    build_envelope,
    compute_action_hash,
)
from actentra_core.evidence import (
    EvidenceTier,
    build_evidence_record,
)
from actentra_core.handoffs import (
    HandoffError,
    UnauthorizedAgentHandoffError,
    build_handoff,
)
from actentra_core.identity import (
    CallerContext,
    DelegationRegistry,
    IdentitySecurityError,
    get_default_delegation_registry,
    make_local_caller_context,
)
from actentra_core.lifecycle import (
    IdempotencyConflictError,
    IdempotencyInFlightError,
    ReconciliationRequiredError,
)
from actentra_core.observability import get_global_metrics
from actentra_core.observations import (
    ObservationError,
    ObservationRecord,
    build_observation,
    build_verification_context,
    compute_verification_context_hash,
)
from actentra_core.policy import lint_policy, load_policy_yaml
from actentra_core.receipts import GENESIS_HASH, SessionRecord, verify_log
from actentra_core.verdict import Decision, Verdict
from actentra_executors.fs import LocalFSExecutor
from actentra_executors.http import ScopedHTTPExecutor
from actentra_executors.sqlite import ScopedSQLiteExecutor
from actentra_executors.verifiers import WorkspaceFileVerifier

ToolExecutorCallable = Callable[[ActionEnvelope, Decision], Any]


class ExecutorRegistry:
    """Registry of scoped action executors available for dispatch."""

    def __init__(self) -> None:
        self._executors: dict[str, ToolExecutorCallable] = {}
        self._workspace_root: str | None = None

    @property
    def workspace_root(self) -> str | None:
        return self._workspace_root

    def register(self, tool_name: str, fn: ToolExecutorCallable) -> None:
        """Register a callable executor for a specific tool name or prefix."""
        self._executors[tool_name.strip().lower()] = fn

    def register_fs(self, workspace_root: str | Path) -> None:
        """Register Scoped Filesystem executor for fs.* tools."""
        executor = LocalFSExecutor(workspace_root)
        self._workspace_root = executor.workspace_root
        for t in ("fs.list", "fs.read", "fs.write", "fs.delete"):
            self.register(t, executor.execute)

    def register_sqlite(self, db_path: str | Path) -> None:
        """Register Scoped SQLite executor for sql.execute."""
        executor = ScopedSQLiteExecutor(db_path)
        self.register("sql.execute", executor.execute)

    def register_http(self, allowed_hosts: list[str] | None = None) -> None:
        """Register Scoped HTTP executor for http.* tools."""
        executor = ScopedHTTPExecutor(allowed_hosts=allowed_hosts)
        for t in ("http.get", "http.post", "http.request"):
            self.register(t, executor.execute)

    def has_executor(self, tool_name: str) -> bool:
        return tool_name.strip().lower() in self._executors

    def get_executor(self, tool_name: str) -> ToolExecutorCallable | None:
        return self._executors.get(tool_name.strip().lower())

    def list_registered_tools(self) -> list[str]:
        return sorted(self._executors.keys())


class AppServices:
    """Unified application services underpinning CLI and Local Web UI."""

    def __init__(
        self,
        boundary: Boundary,
        *,
        executor_registry: ExecutorRegistry | None = None,
        file_verifier: WorkspaceFileVerifier | None = None,
        approval_ttl_seconds: float = 300.0,
        delegation_registry: DelegationRegistry | None = None,
        checkpoint_anchor: CheckpointAnchor | None = None,
        key_ring: KeyRing | None = None,
    ) -> None:
        self.boundary = boundary
        self.registry = executor_registry or ExecutorRegistry()
        self.approval_ttl_seconds = approval_ttl_seconds
        self.delegation_registry = delegation_registry or get_default_delegation_registry()
        self.checkpoint_anchor = checkpoint_anchor
        self.key_ring = key_ring
        if file_verifier is not None:
            self.file_verifier: WorkspaceFileVerifier | None = file_verifier
        elif self.registry.workspace_root is not None:
            self.file_verifier = WorkspaceFileVerifier(self.registry.workspace_root)
        else:
            self.file_verifier = None
        # Recover system state upon service startup
        # (approvals, leases, claims, in-flight lifecycles, pending outcomes)
        self.boundary.receipt_store.recover_system_state()
        self._crossing_lock = threading.RLock()

    def _validate_caller_context(self, caller_context: CallerContext | None) -> None:
        """Validate caller_context does not assert forged, mismatched, or revoked delegation."""
        if caller_context is None:
            return
        if caller_context.delegated_by is not None and not caller_context.is_trusted_operator:
            reg = self.delegation_registry
            auth_id = (
                caller_context.authenticated_principal_id
                if caller_context.authenticated_principal_id
                else caller_context.principal_id
            )
            if caller_context.delegation_grant_id:
                try:
                    reg.validate_grant_binding(
                        caller_context.delegation_grant_id,
                        authenticated_delegatee_id=auth_id,
                        authenticated_delegator_id=caller_context.delegated_by,
                        audience=caller_context.audience,
                    )
                except IdentitySecurityError:
                    default_reg = get_default_delegation_registry()
                    if default_reg is not reg:
                        default_reg.validate_grant_binding(
                            caller_context.delegation_grant_id,
                            authenticated_delegatee_id=auth_id,
                            authenticated_delegator_id=caller_context.delegated_by,
                            audience=caller_context.audience,
                        )
                    else:
                        raise
            else:
                grant = reg.find_active_grant(
                    delegator_id=caller_context.delegated_by,
                    delegatee_id=auth_id,
                    audience=caller_context.audience,
                )
                if grant is None:
                    default_reg = get_default_delegation_registry()
                    if default_reg is not reg:
                        grant = default_reg.find_active_grant(
                            delegator_id=caller_context.delegated_by,
                            delegatee_id=auth_id,
                            audience=caller_context.audience,
                        )
                if grant is None:
                    raise IdentitySecurityError(
                        f"Forged delegation context: principal '{caller_context.principal_id}' "
                        f"has no verified delegation grant from '{caller_context.delegated_by}'"
                    )
                reg.validate_grant_binding(
                    grant,
                    authenticated_delegatee_id=auth_id,
                    authenticated_delegator_id=caller_context.delegated_by,
                    audience=caller_context.audience,
                )

    def _require_scope_or_operator(
        self,
        caller_context: CallerContext | None,
        *scopes: str,
    ) -> None:
        """Validate caller has at least one of the required scopes or is a trusted operator."""
        if caller_context is None:
            return
        self._validate_caller_context(caller_context)
        if caller_context.is_trusted_operator:
            return
        if not any(caller_context.has_scope(s) for s in scopes):
            scope_str = scopes[0] if len(scopes) == 1 else ", ".join(scopes)
            raise IdentitySecurityError(
                f"Principal '{caller_context.principal_id}' lacks '{scope_str}' scope"
            )

    # --- 1. Health & Status ---

    def get_health(self, *, full_verify: bool = False) -> dict[str, Any]:
        """Return runtime health, policy state, and receipt store integrity."""
        db_path = self.boundary.receipt_store.db_path
        pending_list = self.boundary.receipt_store.list_pending_approvals(status="pending")
        db_integrity_ok, db_msg = self.boundary.receipt_store.validate_database_integrity()
        if full_verify:
            vr = verify_log(db_path, verify_envelopes=True)
            total_records = vr.total_records
            integrity_ok = vr.ok and db_integrity_ok
            last_hash = vr.last_hash
        else:
            latest = self.boundary.receipt_store.get_latest_record()
            total_records = self.boundary.receipt_store.record_count()
            integrity_ok = db_integrity_ok
            last_hash = latest.entry_hash if latest else GENESIS_HASH

        return {
            "status": "ok" if db_integrity_ok else "degraded",
            "db_status": "healthy" if db_integrity_ok else f"corrupt: {db_msg}",
            "db_integrity_ok": db_integrity_ok,
            "policy_id": self.boundary.engine.policy.policy_id,
            "policy_version": self.boundary.engine.policy.policy_version,
            "mode": self.boundary.engine.policy.mode,
            "frozen": self.boundary.engine.frozen,
            "total_receipts": total_records,
            "integrity_ok": integrity_ok,
            "last_hash": last_hash,
            "pending_approvals_count": len(pending_list),
            "registered_executors": self.registry.list_registered_tools(),
        }

    def get_metrics(self) -> dict[str, Any]:
        """Return operational telemetry, failure counters, and latency measurements."""
        snapshot = get_global_metrics().snapshot()
        db_ok, _ = self.boundary.receipt_store.validate_database_integrity()
        snapshot["storage"]["database_healthy"] = db_ok
        snapshot["storage"]["database_path"] = str(self.boundary.receipt_store.db_path)
        return snapshot

    # --- 2. Crossing Submission & Lifecycle ---

    def submit_crossing(
        self,
        data: dict[str, Any],
        *,
        execute: bool = False,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any]:
        """Propose, canonicalize, evaluate, and conditionally execute an action."""
        with self._crossing_lock:
            return self._submit_crossing_locked(
                data, execute=execute, caller_context=caller_context
            )

    def _submit_crossing_locked(
        self,
        data: dict[str, Any],
        *,
        execute: bool = False,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any]:
        # Enforce authenticated identity and principal constraints (Stage 0 Task 2)
        raw_agent = data.get("agent_id")
        if raw_agent is None and isinstance(data.get("agent"), dict):
            raw_agent = data["agent"].get("id")
        if caller_context is not None and caller_context.authenticated and raw_agent is None:
            agent_id_claim = caller_context.principal_id
        else:
            agent_id_claim = str(raw_agent or "http-client")
        prov_raw = data.get("provenance", [])
        claimed_trust = None
        if isinstance(prov_raw, list):
            for p in prov_raw:
                if isinstance(p, dict) and p.get("trust") == "trusted":
                    claimed_trust = "trusted"
                    break

        if caller_context is not None:
            try:
                self._validate_caller_context(caller_context)
            except IdentitySecurityError as exc:
                return {
                    "verdict": Verdict.DENY.value,
                    "error": str(exc),
                    "code": "unauthorized_principal",
                    "rule_id": "identity:unauthorized-delegation",
                    "canonical_hash": "sha256:" + ("0" * 64),
                    "risk_tags": ["delegation-forgery"],
                }

            claimed_parent = (
                data.get("parent_agent_id") or data.get("delegated_by") or data.get("parent")
            )
            if claimed_parent is not None:
                clean_parent = str(claimed_parent).strip()
                if not caller_context.is_agent_allowed(clean_parent):
                    return {
                        "verdict": Verdict.DENY.value,
                        "error": (
                            f"Caller-supplied parent identity '{clean_parent}' is not "
                            f"authorized for principal '{caller_context.principal_id}'"
                        ),
                        "code": "unauthorized_principal",
                        "rule_id": "identity:unauthorized-delegation",
                        "canonical_hash": "sha256:" + ("0" * 64),
                        "risk_tags": ["spoofing-attempt", "delegation-forgery"],
                    }

            try:
                caller_context.validate_identity_claims(agent_id_claim, claimed_trust)
            except IdentitySecurityError as exc:
                return {
                    "verdict": Verdict.DENY.value,
                    "error": str(exc),
                    "code": "unauthorized_principal",
                    "rule_id": "identity:unauthorized-principal",
                    "canonical_hash": "sha256:" + ("0" * 64),
                    "risk_tags": ["spoofing-attempt"],
                }
            if not caller_context.has_scope("crossings:propose") and not caller_context.has_scope(
                "crossings:submit"
            ):
                return {
                    "verdict": Verdict.DENY.value,
                    "error": (
                        f"Caller '{caller_context.principal_id}' lacks scope 'crossings:propose'"
                    ),
                    "code": "unauthorized_principal",
                    "rule_id": "identity:scope-denied",
                    "canonical_hash": "sha256:" + ("0" * 64),
                    "risk_tags": ["unauthorized-action"],
                }
            if execute and not caller_context.has_scope("crossings:execute"):
                return {
                    "verdict": Verdict.DENY.value,
                    "error": (
                        f"Caller '{caller_context.principal_id}' lacks scope 'crossings:execute'"
                    ),
                    "code": "unauthorized_principal",
                    "rule_id": "identity:scope-denied",
                    "canonical_hash": "sha256:" + ("0" * 64),
                    "risk_tags": ["unauthorized-action"],
                }

        # Phase 2: Server-controlled session identity and ownership validation
        raw_session_id = data.get("session_id")
        caller_principal = (
            caller_context.authenticated_identity if caller_context else agent_id_claim
        )
        if raw_session_id is not None and str(raw_session_id).strip():
            candidate_sid = str(raw_session_id).strip()
            if len(candidate_sid) > 128:
                return {
                    "verdict": Verdict.HOLD.value,
                    "error": "session_id exceeds maximum length of 128 characters",
                    "rule_id": "kernel:session-id-too-long",
                    "canonical_hash": "sha256:" + ("0" * 64),
                    "risk_tags": [],
                }
            try:
                session_rec = self.validate_session_access(
                    candidate_sid,
                    caller_context=caller_context,
                    auto_create=True,
                )
                session_id = session_rec.session_id
            except IdentitySecurityError as exc:
                return {
                    "verdict": Verdict.DENY.value,
                    "error": str(exc),
                    "code": "unauthorized_principal",
                    "rule_id": "identity:cross-principal-session-access",
                    "canonical_hash": "sha256:" + ("0" * 64),
                    "risk_tags": ["spoofing-attempt", "session-hijack"],
                }
        else:
            # Phase 7: If idempotent replay without explicit session_id, reuse original session
            idemp_key_cand = data.get("idempotency_key")
            existing_idemp_rec = (
                self.boundary.receipt_store.get_idempotency_record(
                    caller_principal, str(idemp_key_cand).strip()
                )
                if idemp_key_cand
                else None
            )
            if existing_idemp_rec is not None:
                orig_lf = self.boundary.receipt_store.get_action_lifecycle(
                    existing_idemp_rec.crossing_id
                )
                session_id = (
                    orig_lf.session_id
                    if orig_lf is not None
                    else self.create_session_record(caller_context=caller_context).session_id
                )
            else:
                session_rec = self.create_session_record(caller_context=caller_context)
                session_id = session_rec.session_id

        prov_items = [
            ProvenanceItem(source=p["source"], trust=p["trust"])
            for p in data.get("provenance", [])
            if isinstance(p, dict) and "source" in p and "trust" in p
        ]
        # Propagate session and principal taint across gateway crossings
        # (cannot be bypassed by declared provenance or by creating a new session)
        if self.boundary.get_session_taint(
            session_id, principal_id=caller_principal
        ) == "untrusted" and not any(p.trust == "untrusted" for p in prov_items):
            prov_items.append(ProvenanceItem(source="session", trust="untrusted"))

        try:
            envelope = build_envelope(
                tool=str(data.get("tool", "")),
                verb=str(data.get("verb", "other")),
                resource=str(data.get("resource", "")),
                params=data.get("params") or {},
                session_id=session_id,
                agent_id=agent_id_claim,
                provenance=prov_items,
                user_goal=data.get("user_goal"),
                idempotency_key=data.get("idempotency_key"),
            )
        except EnvelopeError as exc:
            return {
                "verdict": Verdict.HOLD.value,
                "error": f"Invalid ActionEnvelope: {exc}",
                "rule_id": "kernel:envelope-invalid",
                "canonical_hash": "sha256:" + ("0" * 64),
                "risk_tags": [],
            }

        # Phase 7 (Invariant I16): Durable Idempotency Check & Registration
        effective_principal = caller_principal or envelope.agent.id
        if envelope.action.idempotency_key:
            try:
                cached_idemp = self.boundary.receipt_store.register_idempotency_key(
                    idempotency_key=envelope.action.idempotency_key,
                    principal_id=effective_principal,
                    canonical_hash=envelope.canonical_hash,
                    tool=envelope.action.tool,
                    verb=envelope.action.verb,
                    crossing_id=envelope.crossing_id,
                )
                if cached_idemp is not None:
                    if cached_idemp.status == "completed":
                        return {
                            "verdict": Verdict.ALLOW.value,
                            "rule_id": "idempotency:cached-completed",
                            "crossing_id": cached_idemp.crossing_id,
                            "canonical_hash": cached_idemp.canonical_hash,
                            "executed": True,
                            "outcome": {
                                "status": "success",
                                "result": cached_idemp.response.get("result")
                                if cached_idemp.response
                                else None,
                            },
                            "cached": True,
                        }
                    elif cached_idemp.status == "failed":
                        return {
                            "verdict": Verdict.DENY.value,
                            "rule_id": "idempotency:cached-failed",
                            "crossing_id": cached_idemp.crossing_id,
                            "canonical_hash": cached_idemp.canonical_hash,
                            "executed": False,
                            "outcome": {
                                "status": "failure",
                                "error": cached_idemp.response.get("error", "Action failed")
                                if cached_idemp.response
                                else "Action failed",
                            },
                            "cached": True,
                        }
            except (
                IdempotencyConflictError,
                IdempotencyInFlightError,
                ReconciliationRequiredError,
            ) as exc:
                return {
                    "verdict": Verdict.HOLD.value,
                    "error": str(exc),
                    "code": type(exc).__name__,
                    "rule_id": f"idempotency:{type(exc).__name__}",
                    "canonical_hash": envelope.canonical_hash,
                    "crossing_id": envelope.crossing_id,
                    "risk_tags": [],
                }

        # Phase 7: Initialize action lifecycle state machine (CREATED)
        self.boundary.receipt_store.create_action_lifecycle(
            crossing_id=envelope.crossing_id,
            session_id=envelope.session_id,
            principal_id=effective_principal,
            canonical_hash=envelope.canonical_hash,
            idempotency_key=envelope.action.idempotency_key,
            initial_state="created",
        )

        # Update session and principal taint tracker if this action is untrusted (Phase 2)
        if envelope.max_taint == "untrusted":
            self.boundary.set_session_taint(
                "untrusted",
                session_id=envelope.session_id,
                principal_id=caller_principal,
                caller_context=caller_context,
            )

        # Multi-agent coordination conflict check:
        # mutating operations check for active lease conflicts
        if envelope.action.verb in ("write", "delete", "exec", "admin"):
            conflict = self.boundary.receipt_store.find_resource_conflict(
                resource=envelope.action.resource,
                agent_id=envelope.agent.id,
                mode="exclusive",
            )
            if conflict is not None:
                conflict_decision = Decision(
                    verdict=Verdict.DENY,
                    rule_id="coordination:resource-locked",
                    reason=(
                        f"Resource '{envelope.action.resource}' is locked by agent "
                        f"'{conflict.owner_agent_id}' under lease '{conflict.lease_id}' "
                        f"until {conflict.expires_at}"
                    ),
                    policy_version=self.boundary.engine.policy.policy_version,
                    canonical_hash=envelope.canonical_hash,
                )
                self.boundary.receipt_store.record_decision(envelope, conflict_decision)
                conflict_resp: dict[str, Any] = conflict_decision.to_dict()
                conflict_resp["crossing_id"] = envelope.crossing_id
                conflict_resp["error"] = conflict_decision.reason
                return conflict_resp

        decision = self.boundary.engine.evaluate(envelope)

        # Invariant I5: Persist immutable decision record before any execution
        self.boundary.receipt_store.record_decision(envelope, decision)

        resp: dict[str, Any] = decision.to_dict()
        resp["crossing_id"] = envelope.crossing_id

        # Phase 7: Transition action lifecycle based on evaluation verdict
        if decision.verdict.permits_execution:
            self.boundary.receipt_store.transition_action_state(
                envelope.crossing_id,
                "authorized",
                actor_id="policy",
                reason=decision.reason,
            )
        elif decision.verdict != Verdict.ASK:
            self.boundary.receipt_store.transition_action_state(
                envelope.crossing_id,
                "failed",
                actor_id="policy",
                reason=decision.reason,
            )
            if envelope.action.idempotency_key:
                self.boundary.receipt_store.finalize_idempotency_key(
                    idempotency_key=envelope.action.idempotency_key,
                    principal_id=effective_principal,
                    crossing_id=envelope.crossing_id,
                    status="failed",
                    response={"error": decision.reason},
                )

        # Handle ASK
        if decision.verdict == Verdict.ASK:
            self.boundary.receipt_store.add_pending_approval(
                envelope=envelope,
                decision=decision,
                ttl_seconds=self.approval_ttl_seconds,
            )
            resp["pending_status"] = "pending"
            resp["expires_in_seconds"] = self.approval_ttl_seconds
            return resp

        # Handle ALLOW execution dispatch
        if execute and decision.verdict.permits_execution:
            executor = self.registry.get_executor(envelope.action.tool)
            if executor is not None:
                # Phase 7: Transition to CLAIMED before dispatching execution
                self.boundary.receipt_store.transition_action_state(
                    envelope.crossing_id,
                    "claimed",
                    actor_id=effective_principal,
                    reason="claim_issued",
                )
                try:
                    exec_result = self._dispatch_and_record(
                        envelope, decision, executor, caller_context=caller_context
                    )
                    resp["executed"] = True
                    resp["outcome"] = {"status": "success", "result": exec_result}
                except ActionBlockedError as exc:
                    # _dispatch_and_record raises ActionBlockedError for postcondition
                    # failures and unknown outcomes; these are NOT generic executor failures.
                    resp["executed"] = True  # execution occurred; verification failed
                    outcome_status = (
                        "unknown"
                        if exc.decision.rule_id.startswith("kernel:postcondition-")
                        and "refuted" not in exc.decision.rule_id
                        else "failure"
                    )
                    resp["outcome"] = {
                        "status": outcome_status,
                        "error": exc.decision.reason,
                        "rule_id": exc.decision.rule_id,
                    }
                except Exception as exc:
                    resp["executed"] = False
                    resp["outcome"] = {"status": "failure", "error": type(exc).__name__}
            else:
                resp["executed"] = False
                resp["outcome"] = {
                    "status": "unexecuted",
                    "message": f"No registered executor for tool '{envelope.action.tool}'",
                }

        return resp

    def _dispatch_and_record(
        self,
        envelope: ActionEnvelope,
        decision: Decision,
        executor: ToolExecutorCallable,
        caller_context: CallerContext | None = None,
    ) -> Any:
        """Internal dispatch executing the action and recording the outcome receipt.

        Security invariant: this method enforces the same postcondition verification
        lifecycle as Boundary.execute().  An executor returning success is NOT sufficient
        to record verified-success status when the policy mandates postcondition
        verification.  Success is only promoted after the independent verifier confirms
        the required postcondition.

        Lifecycle states: authorized → claimed → executing → verification_pending
            → succeeded (verified) | failed (refuted/error) | unknown (unverifiable)

        The gateway path, approval path, and all callers of this method share one
        authoritative execution orchestrator.  There is no shorter path to "succeeded".
        """
        # Invariant I3: TOCTOU check immediately before execution
        verify_hash = compute_action_hash(
            envelope_version=envelope.envelope_version,
            session_id=envelope.session_id,
            agent_id=envelope.agent.id,
            action=envelope.action,
        )
        if verify_hash != decision.canonical_hash:
            self.boundary.receipt_store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="failure",
                error="Canonical hash mismatch before execution",
                evidence_status="locally_observed",
            )
            raise ActionBlockedError(
                Decision(
                    verdict=Verdict.HOLD,
                    rule_id="kernel:hash-mismatch",
                    reason="Canonical action hash mismatch before execution",
                    policy_version=decision.policy_version,
                    canonical_hash=envelope.canonical_hash,
                ),
                envelope.crossing_id,
            )

        effective_principal = (
            caller_context.authenticated_identity if caller_context else envelope.agent.id
        )

        # --- Determine postcondition requirements from policy constraints ---
        # This is the security-critical extraction that was absent from the gateway path.
        # The SDK Boundary.execute() path always inspects decision.constraints; we must too.
        policy_require_post = bool(
            decision.constraints.get("require_postcondition")
            or "postcondition" in decision.constraints
            or "required_postconditions" in decision.constraints
            or decision.constraints.get("strict_postconditions")
        )
        policy_post_claim: str | None = decision.constraints.get("postcondition")
        policy_expected_digest: str | None = decision.constraints.get("expected_digest")

        # Resolve effective postcondition claim and expected digest
        effective_claim: str = str(policy_post_claim) if policy_post_claim else "exists"
        effective_expected_digest: str | None = policy_expected_digest

        # Validate postcondition semantics when required
        validated_postcondition: PostconditionSpec | None = None
        if policy_require_post:
            try:
                validated_postcondition = validate_postcondition_semantics(
                    tool=envelope.action.tool,
                    verb=envelope.action.verb,
                    resource=envelope.action.resource,
                    claim=effective_claim,
                    params=envelope.action.params,
                    expected_digest=effective_expected_digest,
                    strict=True,
                )
                effective_claim = validated_postcondition.claim
                effective_expected_digest = validated_postcondition.expected_digest
            except ContextError as exc:
                err_msg = f"Invalid postcondition semantics: {exc}"
                self.boundary.receipt_store.record_outcome(
                    crossing_id=envelope.crossing_id,
                    session_id=envelope.session_id,
                    canonical_hash=envelope.canonical_hash,
                    policy_version=decision.policy_version,
                    status="failure",
                    error=err_msg,
                    reason="invalid_postcondition_semantics",
                    evidence_status="locally_observed",
                )
                self.boundary.receipt_store.transition_action_state(
                    envelope.crossing_id,
                    "failed",
                    actor_id="policy",
                    reason="invalid_postcondition_semantics",
                )
                raise ActionBlockedError(
                    Decision(
                        verdict=Verdict.HOLD,
                        rule_id="kernel:postcondition-invalid",
                        reason=err_msg,
                        policy_version=decision.policy_version,
                        canonical_hash=envelope.canonical_hash,
                    ),
                    envelope.crossing_id,
                ) from exc

        # --- Lifecycle state machine: advance to claimed ---
        cur_lf = self.boundary.receipt_store.get_action_lifecycle(envelope.crossing_id)
        if cur_lf is None:
            self.boundary.receipt_store.create_action_lifecycle(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                principal_id=effective_principal,
                canonical_hash=envelope.canonical_hash,
                initial_state="claimed",
            )
        elif cur_lf.current_state != "claimed":
            if cur_lf.current_state == "created":
                self.boundary.receipt_store.transition_action_state(
                    envelope.crossing_id, "authorized", actor_id="policy", reason="auto_progression"
                )
            if (
                cur_lf.current_state in ("created", "authorized")
                or cur_lf.current_state == "approved"
            ):
                self.boundary.receipt_store.transition_action_state(
                    envelope.crossing_id,
                    "claimed",
                    actor_id=effective_principal,
                    reason="claim_issued",
                )

        # --- Issue durable execution claim (matches SDK Boundary.execute() invariant) ---
        appr_or_war = (
            f"approval:{envelope.crossing_id}"
            if decision.rule_id.endswith(":approved")
            else None
        )
        try:
            claim = self.boundary.receipt_store.issue_execution_claim(
                crossing_id=envelope.crossing_id,
                executor_principal_id=effective_principal,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                approval_or_warrant_id=appr_or_war,
            )
        except Exception:
            # If claim issuance fails (e.g. duplicate), fall back to no-claim for
            # backwards-compat with approved-crossing path that may already hold a claim.
            claim = None

        # Phase 7: Transition to EXECUTING
        self.boundary.receipt_store.transition_action_state(
            envelope.crossing_id,
            "executing",
            actor_id=effective_principal,
            reason="gateway_dispatch",
        )
        get_global_metrics().increment("executions_dispatched")
        t0 = time.time()

        try:
            result = executor(envelope, decision)
        except Exception as exc:
            err_label = type(exc).__name__
            if self.boundary.secrets_broker is not None:
                err_label = self.boundary.secrets_broker.redact(err_label)
            if claim is not None:
                with contextlib.suppress(Exception):
                    self.boundary.receipt_store.consume_execution_claim(
                        claim.claim_id,
                        executor_principal_id=effective_principal,
                        crossing_id=envelope.crossing_id,
                        canonical_hash=envelope.canonical_hash,
                        approval_or_warrant_id=claim.approval_or_warrant_id,
                        verification_status="error",
                    )
            self.boundary.receipt_store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="failure",
                error=err_label,
                evidence_status="locally_observed",
            )
            self.boundary.receipt_store.transition_action_state(
                envelope.crossing_id,
                "failed",
                actor_id=effective_principal,
                reason=err_label,
            )
            if envelope.action.idempotency_key:
                self.boundary.receipt_store.finalize_idempotency_key(
                    idempotency_key=envelope.action.idempotency_key,
                    principal_id=effective_principal,
                    crossing_id=envelope.crossing_id,
                    status="failed",
                    response={"error": err_label},
                )
            get_global_metrics().increment("executions_failed")
            raise

        res_hash: str | None = None
        try:
            res_hash = hash_canonical(result)
        except Exception:
            res_hash = None

        # =====================================================================
        # SECURITY CRITICAL: Postcondition verification gate
        #
        # When policy mandates postcondition verification (require_postcondition,
        # postcondition constraint, etc.) success may ONLY be recorded AFTER the
        # independent verifier confirms the required postcondition.
        #
        # An executor returning without raising is NOT proof of verified success.
        # Skipping this gate is the exact bypass reported in the audit.
        # =====================================================================

        if not policy_require_post:
            # No postcondition required: record locally-observed success (unchanged from before)
            if claim is not None:
                with contextlib.suppress(Exception):
                    self.boundary.receipt_store.consume_execution_claim(
                        claim.claim_id,
                        executor_principal_id=effective_principal,
                        crossing_id=envelope.crossing_id,
                        canonical_hash=envelope.canonical_hash,
                        approval_or_warrant_id=claim.approval_or_warrant_id,
                        result_digest=res_hash,
                        verification_status="unverified",
                    )
            self.boundary.receipt_store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="success",
                result_hash=res_hash,
                evidence_status="locally_observed",
            )
            self.boundary.receipt_store.transition_action_state(
                envelope.crossing_id,
                "succeeded",
                actor_id=effective_principal,
                reason="gateway_execution_completed",
            )
            if envelope.action.idempotency_key:
                self.boundary.receipt_store.finalize_idempotency_key(
                    idempotency_key=envelope.action.idempotency_key,
                    principal_id=effective_principal,
                    crossing_id=envelope.crossing_id,
                    status="completed",
                    result_hash=res_hash,
                    response={"result": result, "status": "success"},
                )
            get_global_metrics().increment("executions_succeeded")
            get_global_metrics().record_latency(
                f"gateway:{envelope.action.tool}", time.time() - t0
            )
            with contextlib.suppress(Exception):
                ev = build_evidence_record(
                    crossing_id=envelope.crossing_id,
                    tier=EvidenceTier.LOCALLY_OBSERVED,
                    trust_domain="local_boundary",
                    collector=f"executor:{envelope.action.tool}",
                    details={"result_hash": res_hash, "executed": True},
                )
                self.boundary.receipt_store.record_evidence(ev)
            self.boundary.engine.budget_tracker.record_usage(
                envelope,
                principal_id=(
                    caller_context.authenticated_identity if caller_context else envelope.agent.id
                ),
            )
            return result

        # --- Postcondition verification required ---
        # Transition to verification_pending before invoking the verifier.
        self.boundary.receipt_store.transition_action_state(
            envelope.crossing_id,
            "verification_pending",
            actor_id=effective_principal,
            reason="verifying_postcondition",
        )

        verifier = self.file_verifier  # AppServices verifier (WorkspaceFileVerifier or None)

        if verifier is None:
            # Fail closed: postcondition required but no verifier configured.
            # Record unknown (not success) and require reconciliation.
            if claim is not None:
                with contextlib.suppress(Exception):
                    self.boundary.receipt_store.consume_execution_claim(
                        claim.claim_id,
                        executor_principal_id=effective_principal,
                        crossing_id=envelope.crossing_id,
                        canonical_hash=envelope.canonical_hash,
                        approval_or_warrant_id=claim.approval_or_warrant_id,
                        result_digest=res_hash,
                        verification_status="unknown",
                    )
            self.boundary.receipt_store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="unknown",
                result_hash=res_hash,
                error=(
                    "Postcondition verification required by policy but no verifier is "
                    "configured on AppServices; failing closed"
                ),
                reason="postcondition_unverified_no_verifier",
                evidence_status="unknown",
            )
            self.boundary.receipt_store.transition_action_state(
                envelope.crossing_id,
                "unknown",
                actor_id=effective_principal,
                reason="postcondition_unverified_no_verifier",
            )
            if envelope.action.idempotency_key:
                self.boundary.receipt_store.finalize_idempotency_key(
                    idempotency_key=envelope.action.idempotency_key,
                    principal_id=effective_principal,
                    crossing_id=envelope.crossing_id,
                    status="reconciliation_required",
                    result_hash=res_hash,
                    response={"status": "unknown"},
                )
            get_global_metrics().increment("executions_unknown")
            # Raise: gateway callers must handle this as a non-success outcome.
            raise ActionBlockedError(
                Decision(
                    verdict=Verdict.HOLD,
                    rule_id="kernel:postcondition-verifier-missing",
                    reason=(
                        "Postcondition verification required by policy but no verifier "
                        "is configured; execution outcome recorded as unknown"
                    ),
                    policy_version=decision.policy_version,
                    canonical_hash=envelope.canonical_hash,
                ),
                envelope.crossing_id,
            )

        # --- Run independent verifier ---
        target_res = (
            validated_postcondition.resource
            if validated_postcondition
            else envelope.action.resource
        )
        target_claim = (
            validated_postcondition.claim if validated_postcondition else effective_claim
        )
        target_digest = (
            validated_postcondition.expected_digest
            if validated_postcondition
            else effective_expected_digest
        )

        obs = None
        try:
            kwargs: dict[str, Any] = {"crossing_id": envelope.crossing_id}
            if target_digest is not None:
                kwargs["expected_digest"] = target_digest
            try:
                obs = verifier.verify(resource=target_res, claim=target_claim, **kwargs)
            except TypeError:
                obs = verifier.verify(resource=target_res, claim=target_claim)
        except Exception as exc:
            obs = build_observation(
                subject_resource=target_res,
                claim=target_claim,
                status="error",
                verifier_id=getattr(verifier, "verifier_id", "actentra.gateway.verifier.unknown"),
                verifier_version=getattr(verifier, "verifier_version", "1.0.0"),
                trust_domain="local_host",
                crossing_id=envelope.crossing_id,
                error=f"Verifier raised exception: {exc}",
            )

        if obs.status == "verified":
            # SUCCESS: postcondition independently confirmed.
            if claim is not None:
                with contextlib.suppress(Exception):
                    self.boundary.receipt_store.consume_execution_claim(
                        claim.claim_id,
                        executor_principal_id=effective_principal,
                        crossing_id=envelope.crossing_id,
                        canonical_hash=envelope.canonical_hash,
                        approval_or_warrant_id=claim.approval_or_warrant_id,
                        result_digest=res_hash,
                        evidence_id=obs.observation_id,
                        verification_status="verified",
                    )
            self.boundary.receipt_store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="success",
                result_hash=res_hash,
                evidence_status="externally_verified",
                observation=obs,
            )
            self.boundary.receipt_store.transition_action_state(
                envelope.crossing_id,
                "succeeded",
                actor_id=obs.verifier_id,
                reason="postcondition_verified",
            )
            if envelope.action.idempotency_key:
                self.boundary.receipt_store.finalize_idempotency_key(
                    idempotency_key=envelope.action.idempotency_key,
                    principal_id=effective_principal,
                    crossing_id=envelope.crossing_id,
                    status="completed",
                    result_hash=res_hash,
                    response={"result": result, "status": "success"},
                )
            get_global_metrics().increment("executions_succeeded")
            get_global_metrics().record_latency(
                f"gateway:{envelope.action.tool}", time.time() - t0
            )
            # Record externally-verified evidence and causal link
            with contextlib.suppress(Exception):
                ev = build_evidence_record(
                    crossing_id=envelope.crossing_id,
                    tier=EvidenceTier.EXTERNALLY_VERIFIED,
                    trust_domain="verifier:workspace",
                    collector=obs.verifier_id,
                    details={
                        "observation_id": obs.observation_id,
                        "resource": obs.subject_resource,
                        "claim": obs.claim,
                        "status": obs.status,
                        "observed_digest": obs.observed_digest,
                    },
                    expires_at=obs.expires_at,
                )
                self.boundary.receipt_store.record_evidence(ev)
            with contextlib.suppress(Exception):
                link = CausalLink(
                    link_id=generate_link_id(),
                    link_version="1",
                    source_id=envelope.crossing_id,
                    source_type="crossing",
                    relation="verifies",
                    target_id=obs.observation_id,
                    target_type="observation",
                    created_at=utc_iso(),
                )
                self.boundary.receipt_store.record_causal_link(link)
            self.boundary.engine.budget_tracker.record_usage(
                envelope,
                principal_id=(
                    caller_context.authenticated_identity if caller_context else envelope.agent.id
                ),
            )
            return result

        elif obs.status == "refuted":
            # FAILURE: postcondition independently refuted.
            if claim is not None:
                with contextlib.suppress(Exception):
                    self.boundary.receipt_store.consume_execution_claim(
                        claim.claim_id,
                        executor_principal_id=effective_principal,
                        crossing_id=envelope.crossing_id,
                        canonical_hash=envelope.canonical_hash,
                        approval_or_warrant_id=claim.approval_or_warrant_id,
                        result_digest=res_hash,
                        evidence_id=obs.observation_id,
                        verification_status="refuted",
                    )
            err_msg = (
                f"Postcondition refuted: claim '{target_claim}' on resource '{target_res}'"
            )
            if obs.error:
                err_msg += f" ({obs.error})"
            self.boundary.receipt_store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="failure",
                result_hash=res_hash,
                error=err_msg,
                reason="postcondition_refuted",
                evidence_status="locally_observed",
                observation=obs,
            )
            self.boundary.receipt_store.transition_action_state(
                envelope.crossing_id,
                "failed",
                actor_id=obs.verifier_id,
                reason="postcondition_refuted",
            )
            if envelope.action.idempotency_key:
                self.boundary.receipt_store.finalize_idempotency_key(
                    idempotency_key=envelope.action.idempotency_key,
                    principal_id=effective_principal,
                    crossing_id=envelope.crossing_id,
                    status="failed",
                    response={"error": "postcondition_refuted"},
                )
            get_global_metrics().increment("executions_failed")
            raise ActionBlockedError(
                Decision(
                    verdict=Verdict.DENY,
                    rule_id="kernel:postcondition-refuted",
                    reason=err_msg,
                    policy_version=decision.policy_version,
                    canonical_hash=envelope.canonical_hash,
                ),
                envelope.crossing_id,
            )

        else:
            # UNKNOWN: verifier returned an indeterminate status (error, stale, etc.)
            status_label = obs.status
            if claim is not None:
                with contextlib.suppress(Exception):
                    self.boundary.receipt_store.consume_execution_claim(
                        claim.claim_id,
                        executor_principal_id=effective_principal,
                        crossing_id=envelope.crossing_id,
                        canonical_hash=envelope.canonical_hash,
                        approval_or_warrant_id=claim.approval_or_warrant_id,
                        result_digest=res_hash,
                        evidence_id=obs.observation_id,
                        verification_status=status_label,
                    )
            err_msg = (
                f"Postcondition verification status is '{status_label}' "
                f"for claim '{target_claim}'"
            )
            if obs.error:
                err_msg += f": {obs.error}"
            ev_status = "stale" if status_label == "stale" else "unknown"
            self.boundary.receipt_store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="unknown",
                result_hash=res_hash,
                error=err_msg,
                reason=f"postcondition_{status_label}",
                evidence_status=ev_status,
                observation=obs,
            )
            self.boundary.receipt_store.transition_action_state(
                envelope.crossing_id,
                "unknown",
                actor_id=obs.verifier_id,
                reason=f"postcondition_{status_label}",
            )
            if envelope.action.idempotency_key:
                self.boundary.receipt_store.finalize_idempotency_key(
                    idempotency_key=envelope.action.idempotency_key,
                    principal_id=effective_principal,
                    crossing_id=envelope.crossing_id,
                    status="reconciliation_required",
                    result_hash=res_hash,
                    response={"status": "unknown", "error": obs.error},
                )
            get_global_metrics().increment("executions_unknown")
            raise ActionBlockedError(
                Decision(
                    verdict=Verdict.HOLD,
                    rule_id=f"kernel:postcondition-{status_label}",
                    reason=err_msg,
                    policy_version=decision.policy_version,
                    canonical_hash=envelope.canonical_hash,
                ),
                envelope.crossing_id,
            )

    # --- 3. Approvals Management ---

    def list_pending_approvals(
        self,
        *,
        status: str | None = "pending",
        limit: int = 100,
        caller_context: CallerContext | None = None,
    ) -> list[dict[str, Any]]:
        """List pending approvals from SQLite store with scope and object-level authorization."""
        self._require_scope_or_operator(caller_context, "approvals:read", "crossings:read")

        records = self.boundary.receipt_store.list_pending_approvals(status=status, limit=limit)
        results: list[dict[str, Any]] = []
        for r in records:
            d = r.to_dict()
            # Object-level filtering and parameter redaction for non-operators
            if caller_context is not None and not caller_context.is_trusted_operator:
                is_owner = False
                sess = self.boundary.receipt_store.get_session(r.session_id)
                auth_id = caller_context.authenticated_identity.lower()
                if (sess and sess.principal_id.lower() == auth_id) or (
                    caller_context.is_agent_allowed(r.session_id)
                    or caller_context.principal_id.lower() == r.session_id.lower()
                ):
                    is_owner = True

                if (
                    not is_owner
                    and not caller_context.is_approver
                    and not caller_context.has_scope("approvals:read_all")
                ):
                    continue  # Non-owner cannot see other principals' pending approvals

                if not is_owner and not caller_context.is_trusted_operator:
                    # Redact sensitive parameters for non-owners/non-operators
                    d["params"] = {"_redacted": "UNAUTHORIZED_RESOURCE_ACCESS"}
            results.append(d)
        return results

    def get_pending_approval(
        self,
        crossing_id: str,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any] | None:
        """Get detail for a specific crossing approval, enforcing object-level authorization."""
        self._require_scope_or_operator(caller_context, "approvals:read", "crossings:read")

        r = self.boundary.receipt_store.get_pending_approval(crossing_id)
        if r is None:
            return None
        d = r.to_dict()
        if caller_context is not None and not caller_context.is_trusted_operator:
            is_owner = False
            sess = self.boundary.receipt_store.get_session(r.session_id)
            auth_id = caller_context.authenticated_identity.lower()
            if (sess and sess.principal_id.lower() == auth_id) or (
                caller_context.is_agent_allowed(r.session_id)
                or caller_context.principal_id.lower() == r.session_id.lower()
            ):
                is_owner = True

            if (
                not is_owner
                and not caller_context.is_approver
                and not caller_context.has_scope("approvals:read_all")
            ):
                raise IdentitySecurityError(
                    f"Principal '{caller_context.principal_id}' is not authorized to access "
                    f"approval '{crossing_id}' belonging to another principal"
                )
            if not is_owner and not caller_context.is_trusted_operator:
                d["params"] = {"_redacted": "UNAUTHORIZED_RESOURCE_ACCESS"}
        return d

    def get_action_lifecycle(
        self,
        crossing_id: str,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any] | None:
        """Get lifecycle state and details for a crossing, enforcing authorization."""
        self._require_scope_or_operator(caller_context, "crossings:read", "approvals:read")
        rec = self.boundary.receipt_store.get_action_lifecycle(crossing_id)
        if rec is None:
            return None
        return rec.to_dict()

    def list_action_transitions(
        self,
        crossing_id: str,
        caller_context: CallerContext | None = None,
    ) -> list[dict[str, Any]]:
        """List historical state transitions for a crossing, enforcing authorization."""
        self._require_scope_or_operator(caller_context, "crossings:read", "approvals:read")
        transitions = self.boundary.receipt_store.list_action_transitions(crossing_id)
        return [t.to_dict() for t in transitions]

    def get_crossing(
        self,
        crossing_id: str,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any] | None:
        """Get unified crossing status including lifecycle, approval, and transitions."""
        self._require_scope_or_operator(caller_context, "crossings:read", "approvals:read")
        lf = self.boundary.receipt_store.get_action_lifecycle(crossing_id)
        appr = self.get_pending_approval(crossing_id, caller_context=caller_context)
        if lf is None and appr is None:
            return None

        transitions = self.boundary.receipt_store.list_action_transitions(crossing_id)
        return {
            "crossing_id": crossing_id,
            "lifecycle": lf.to_dict() if lf is not None else None,
            "approval": appr,
            "transitions": [t.to_dict() for t in transitions],
        }

    def resolve_approval(
        self,
        crossing_id: str,
        *,
        approved: bool,
        execute: bool = False,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any]:
        """Resolve a pending crossing (approve or deny) with optional execution dispatch."""
        if caller_context is not None:
            if not caller_context.is_approver:
                return {
                    "error": (
                        f"Principal '{caller_context.principal_id}' is not authorized to "
                        "resolve approvals"
                    )
                }
            if execute and not caller_context.has_scope("crossings:execute"):
                return {
                    "error": (
                        f"Principal '{caller_context.principal_id}' lacks 'crossings:execute' scope"
                    )
                }

        res = self.boundary.receipt_store.resolve_pending_approval(
            crossing_id,
            approved=approved,
            approver_id=caller_context.principal_id if caller_context else None,
        )
        if res is None:
            return {
                "error": f"Pending crossing '{crossing_id}' not found, already resolved, or expired"
            }

        if approved:
            self.boundary.grant_approval(
                canonical_hash=res.canonical_hash,
                session_id=res.session_id,
            )
            approver = caller_context.principal_id if caller_context else "operator"
            cur_lf = self.boundary.receipt_store.get_action_lifecycle(crossing_id)
            if cur_lf:
                if cur_lf.current_state == "created":
                    self.boundary.receipt_store.transition_action_state(
                        crossing_id, "authorized", actor_id="policy", reason="ask_evaluated"
                    )
                if cur_lf.current_state in ("created", "authorized"):
                    self.boundary.receipt_store.transition_action_state(
                        crossing_id, "approved", actor_id=approver, reason="human_approved"
                    )
        else:
            approver = caller_context.principal_id if caller_context else "operator"
            cur_lf = self.boundary.receipt_store.get_action_lifecycle(crossing_id)
            if cur_lf and cur_lf.current_state in ("created", "authorized"):
                self.boundary.receipt_store.transition_action_state(
                    crossing_id, "failed", actor_id=approver, reason="human_rejected"
                )

        resp: dict[str, Any] = {
            "crossing_id": crossing_id,
            "status": "approved" if approved else "rejected",
            "canonical_hash": res.canonical_hash,
        }

        if approved and execute:
            exec_res = self.execute_approved_crossing(crossing_id, caller_context=caller_context)
            resp["execution"] = exec_res

        return resp

    def execute_approved_crossing(
        self,
        crossing_id: str,
        *,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any]:
        """Execute a previously approved crossing through registered executor."""
        with self._crossing_lock:
            return self._execute_approved_crossing_locked(
                crossing_id, caller_context=caller_context
            )

    def _execute_approved_crossing_locked(
        self,
        crossing_id: str,
        *,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any]:
        p = self.boundary.receipt_store.get_pending_approval(crossing_id)
        if p is None:
            return {"error": f"Crossing '{crossing_id}' not found"}
        if p.status != "approved":
            return {
                "error": f"Crossing '{crossing_id}' is not in approved state (status={p.status})"
            }
        if p.expires_at <= time.time():
            return {"error": f"Crossing '{crossing_id}' approval has expired"}

        raw_env = self.boundary.receipt_store.get_envelope(crossing_id)
        if raw_env is None:
            return {"error": f"Context envelope for '{crossing_id}' missing from store"}

        action_data = raw_env.get("action") or {}
        agent_data = raw_env.get("agent") or {}

        if caller_context is not None:
            if not caller_context.has_scope("crossings:execute"):
                return {
                    "error": (
                        f"Principal '{caller_context.principal_id}' lacks 'crossings:execute' scope"
                    )
                }
            if caller_context.authenticated and not caller_context.is_trusted_operator:
                env_agent_id = str(agent_data.get("id", ""))
                if env_agent_id and not caller_context.is_agent_allowed(env_agent_id):
                    return {
                        "error": (
                            f"Principal '{caller_context.principal_id}' is not authorized to "
                            f"execute crossing for agent '{env_agent_id}'"
                        )
                    }
        prov_items = [
            ProvenanceItem(source=item["source"], trust=item["trust"])
            for item in raw_env.get("provenance", [])
            if isinstance(item, dict) and "source" in item and "trust" in item
        ]
        envelope = build_envelope(
            tool=str(action_data.get("tool", "")),
            verb=str(action_data.get("verb", "other")),
            resource=str(action_data.get("resource", "")),
            params=action_data.get("params") or {},
            session_id=str(raw_env.get("session_id", "default")),
            agent_id=str(agent_data.get("id", "http-client")),
            provenance=prov_items,
            user_goal=raw_env.get("user_goal"),
            crossing_id=crossing_id,
        )

        if envelope.canonical_hash != p.canonical_hash:
            return {
                "error": "Canonical hash mismatch between pending approval and stored envelope",
                "crossing_id": crossing_id,
            }

        decision = self.boundary.engine.evaluate(envelope)
        if decision.verdict == Verdict.ASK:
            # Crossing was approved by human operator and verified in SQLite pending_approvals
            decision = Decision(
                verdict=Verdict.ALLOW,
                rule_id=f"{decision.rule_id}:approved",
                reason=f"Human approved: {decision.reason}",
                policy_version=decision.policy_version,
                canonical_hash=decision.canonical_hash,
                risk_tags=decision.risk_tags,
                constraints=decision.constraints,
                shadow=decision.shadow,
                would_verdict=decision.would_verdict,
            )
        # Invariant: Re-evaluation must permit execution (Finding 1)
        if not decision.verdict.permits_execution:
            return {
                "error": (
                    f"Execution blocked: verdict={decision.verdict.value} "
                    f"rule={decision.rule_id} reason={decision.reason}"
                ),
                "verdict": decision.verdict.value,
                "crossing_id": crossing_id,
            }

        executor = self.registry.get_executor(envelope.action.tool)
        if executor is None:
            return {
                "error": f"No registered executor for tool '{envelope.action.tool}'",
                "crossing_id": crossing_id,
            }

        # Atomically claim approval before execution dispatch
        # to prevent concurrent duplicates (Finding 1)
        claimed = self.boundary.receipt_store.claim_approval_for_execution(crossing_id)
        if not claimed:
            return {
                "error": (
                    f"Crossing '{crossing_id}' could not be claimed for execution "
                    "(already claimed, consumed, or expired)"
                ),
                "crossing_id": crossing_id,
            }

        # Consume any corresponding in-memory approval grant
        self.boundary.consume_approval(envelope.canonical_hash, session_id=envelope.session_id)

        try:
            result = self._dispatch_and_record(
                envelope, decision, executor, caller_context=caller_context
            )
            return {"status": "success", "result": result, "crossing_id": crossing_id}
        except ActionBlockedError as exc:
            # ActionBlockedError from _dispatch_and_record means postcondition verification
            # failed or produced an unknown outcome. This is NOT a simple executor failure.
            outcome_status = (
                "unknown"
                if exc.decision.rule_id.startswith("kernel:postcondition-")
                and "refuted" not in exc.decision.rule_id
                else "failure"
            )
            return {
                "status": outcome_status,
                "error": exc.decision.reason,
                "rule_id": exc.decision.rule_id,
                "crossing_id": crossing_id,
            }
        except Exception as exc:
            return {"status": "failure", "error": type(exc).__name__, "crossing_id": crossing_id}

    def claim_crossing_for_execution(
        self,
        crossing_id: str,
        *,
        caller_context: CallerContext | None = None,
        ttl_seconds: float = 300.0,
    ) -> dict[str, Any]:
        """Issue a one-time execution claim for an approved/allowed crossing."""
        dec_rec = self.boundary.receipt_store.get_decision_receipt(crossing_id)
        if dec_rec is None:
            return {"error": f"Crossing '{crossing_id}' not found", "code": "not_found"}

        if dec_rec.verdict not in ("allow", "allow_with_constraints"):
            p = self.boundary.receipt_store.get_pending_approval(crossing_id)
            if p is None or p.status != "approved":
                return {
                    "error": (
                        f"Cannot claim crossing '{crossing_id}' with non-allowed decision "
                        f"(verdict={dec_rec.verdict})"
                    ),
                    "code": "not_permitted",
                }

        outcome_rec = self.boundary.receipt_store.get_outcome_receipt(crossing_id)
        if outcome_rec is not None:
            return {
                "error": f"Crossing '{crossing_id}' has already been executed",
                "code": "already_executed",
            }

        raw_env = self.boundary.receipt_store.get_envelope(crossing_id)
        if raw_env is None:
            return {
                "error": f"Crossing envelope for '{crossing_id}' missing from store",
                "code": "not_found",
            }

        agent_data = raw_env.get("agent") or {}
        env_agent_id = str(agent_data.get("id", ""))
        executor_principal = "anonymous_executor"

        if caller_context is not None:
            if not caller_context.has_scope("crossings:claim") and not caller_context.has_scope(
                "crossings:execute"
            ):
                return {
                    "error": (
                        f"Principal '{caller_context.principal_id}' lacks "
                        "'crossings:claim' or 'crossings:execute' scope"
                    ),
                    "code": "forbidden",
                }
            if (
                caller_context.authenticated
                and not caller_context.is_trusted_operator
                and env_agent_id
                and not caller_context.is_agent_allowed(env_agent_id)
            ):
                return {
                    "error": (
                        f"Principal '{caller_context.principal_id}' is not authorized to "
                        f"claim crossing for agent '{env_agent_id}'"
                    ),
                    "code": "forbidden",
                }
            executor_principal = caller_context.principal_id

        try:
            claim = self.boundary.receipt_store.issue_execution_claim(
                crossing_id=crossing_id,
                executor_principal_id=executor_principal,
                session_id=raw_env["session_id"],
                canonical_hash=raw_env["canonical_hash"],
                ttl_seconds=ttl_seconds,
            )
            return {
                "claim_id": claim.claim_id,
                "crossing_id": crossing_id,
                "executor_principal_id": executor_principal,
                "expires_at": claim.expires_at,
                "status": claim.status,
            }
        except Exception as exc:
            return {"error": str(exc), "code": "claim_failed"}

    def _normalize_bound_resource(self, resource: str) -> str:
        """Canonicalize a resource identifier using the same representation as policy/verifiers."""
        clean = canonicalize_unicode(resource).strip()
        if clean.lower().startswith("path:"):
            raw_path = clean[5:]
            base = self.file_verifier.workspace_root if self.file_verifier is not None else None
            try:
                canon = canonicalize_windows_path(raw_path, base_dir=base, resolve_fs=True)
                return f"path:{canon}"
            except CanonicalizationError:
                return canonicalize_resource(clean)
        return canonicalize_resource(clean)

    def _resolve_crossing_postcondition(
        self,
        raw_env: dict[str, Any],
        dec_constraints: dict[str, Any],
    ) -> tuple[str, str, str | None]:
        """Resolve canonical authorized resource, expected claim, and expected digest."""
        action_data = raw_env.get("action") or {}
        tool = str(action_data.get("tool", ""))
        verb = str(action_data.get("verb", "other"))
        raw_res = str(action_data.get("resource", ""))
        params = action_data.get("params") or {}
        authorized_resource = self._normalize_bound_resource(raw_res)

        policy_post_claim: str | None = dec_constraints.get("postcondition")
        policy_expected_digest: str | None = dec_constraints.get("expected_digest")

        req_posts = dec_constraints.get("required_postconditions")
        if isinstance(req_posts, (list, tuple)) and req_posts:
            first_post = req_posts[0]
            if isinstance(first_post, dict):
                if policy_post_claim is None and first_post.get("claim"):
                    policy_post_claim = str(first_post["claim"])
                if policy_expected_digest is None and first_post.get("expected_digest"):
                    policy_expected_digest = str(first_post["expected_digest"])
                if first_post.get("resource"):
                    spec_res = self._normalize_bound_resource(str(first_post["resource"]))
                    if spec_res != authorized_resource:
                        raise ContextError(
                            f"Postcondition resource '{spec_res}' does not match "
                            f"authorized action resource '{authorized_resource}'"
                        )

        effective_claim = str(policy_post_claim) if policy_post_claim else "exists"
        validated = validate_postcondition_semantics(
            tool=tool,
            verb=verb,
            resource=authorized_resource,
            claim=effective_claim,
            params=params,
            expected_digest=policy_expected_digest,
            strict=True,
        )
        return (
            authorized_resource,
            validated.claim,
            validated.expected_digest.lower() if validated.expected_digest else None,
        )

    def _validate_bound_observation_for_outcome(
        self,
        obs: ObservationRecord,
        *,
        crossing_id: str,
        claim_id: str,
        executor_principal_id: str,
        canonical_action_hash: str,
        authorized_resource: str,
        expected_claim: str,
        expected_digest: str | None,
        policy_version: str,
    ) -> str | None:
        """Validate all cryptographic, resource, claim, postcondition, and identity bindings."""
        if not obs.verify_integrity():
            return f"Observation '{obs.observation_id}' failed cryptographic integrity verification"
        if obs.consumed_at is not None:
            return f"Observation '{obs.observation_id}' has already been consumed"
        if obs.crossing_id != crossing_id:
            return (
                f"Observation '{obs.observation_id}' is bound to crossing '{obs.crossing_id}', "
                f"not '{crossing_id}'"
            )
        if obs.claim_id != claim_id:
            return (
                f"Observation '{obs.observation_id}' is bound to claim '{obs.claim_id}', "
                f"not '{claim_id}'"
            )
        if obs.canonical_action_hash != canonical_action_hash:
            return (
                f"Observation '{obs.observation_id}' action hash '{obs.canonical_action_hash}' "
                f"does not match crossing action hash '{canonical_action_hash}'"
            )
        if obs.executor_principal_id != executor_principal_id:
            return (
                f"Observation '{obs.observation_id}' executor '{obs.executor_principal_id}' "
                f"does not match claim executor '{executor_principal_id}'"
            )
        if obs.policy_version != policy_version:
            return (
                f"Observation '{obs.observation_id}' policy version '{obs.policy_version}' "
                f"does not match decision policy version '{policy_version}'"
            )
        if (
            not obs.verification_id
            or not obs.verifier_principal_id
            or not obs.verification_context_hash
        ):
            return (
                f"Observation '{obs.observation_id}' is missing canonical verification context "
                "binding"
            )

        try:
            obs_res = self._normalize_bound_resource(obs.subject_resource)
        except Exception as exc:
            return f"Observation resource '{obs.subject_resource}' failed normalization: {exc}"

        if obs_res != authorized_resource:
            return (
                f"Observation resource '{obs_res}' does not match authorized crossing resource "
                f"'{authorized_resource}'"
            )

        expected_ctx_hash = compute_verification_context_hash(
            verification_id=obs.verification_id,
            crossing_id=crossing_id,
            canonical_action_hash=canonical_action_hash,
            authorized_resource=authorized_resource,
            expected_postcondition=expected_claim,
            expected_digest=expected_digest,
            claim_id=claim_id,
            executor_principal_id=executor_principal_id,
            verifier_principal_id=obs.verifier_principal_id,
            policy_version=policy_version,
            observed_at=obs.observed_at,
            expires_at=obs.expires_at or "",
        )
        if not hmac.compare_digest(obs.verification_context_hash, expected_ctx_hash):
            return (
                f"Observation '{obs.observation_id}' verification context hash mismatch "
                "(context tampering or binding mismatch)"
            )

        if obs.status != "verified":
            return f"Observation '{obs.observation_id}' has status '{obs.status}', not 'verified'"

        clean_obs_claim = canonicalize_unicode(obs.claim).strip().lower()
        if clean_obs_claim != expected_claim:
            return (
                f"Observation postcondition claim '{clean_obs_claim}' does not satisfy "
                f"required postcondition '{expected_claim}'"
            )

        if expected_claim == "digest_match":
            if not expected_digest:
                return "Missing expected_digest for 'digest_match' postcondition"
            if not obs.observed_digest:
                return f"Observation '{obs.observation_id}' is missing observed_digest"
            if obs.observed_digest.strip().lower() != expected_digest.strip().lower():
                return (
                    f"Observed digest '{obs.observed_digest}' does not match expected digest "
                    f"'{expected_digest}'"
                )
        elif expected_claim == "exists":
            if obs.metadata.get("exists") is not True:
                return f"Observation '{obs.observation_id}' did not confirm resource existence"
            if authorized_resource.startswith("path:") and not obs.observed_digest:
                return f"Observation '{obs.observation_id}' is missing file digest for 'exists'"
        elif expected_claim == "absent" and obs.metadata.get("exists") is not False:
            return f"Observation '{obs.observation_id}' did not confirm resource absence"

        if obs.expires_at is None or not obs.is_fresh():
            return f"Observation '{obs.observation_id}' is expired or missing expiry"

        verifier_id_low = obs.verifier_id.strip().lower()
        if not verifier_id_low or verifier_id_low.startswith(
            ("caller", "llm", "agent", "anonymous")
        ):
            return f"Untrusted observation producer '{obs.verifier_id}'"

        return None

    def record_external_outcome(
        self,
        crossing_id: str,
        *,
        status: Literal["success", "failure", "unknown"],
        claim_id: str | None = None,
        observation_id: str | None = None,
        result_hash: str | None = None,
        error: str | None = None,
        caller_context: CallerContext | None = None,
        require_claim: bool = False,
    ) -> dict[str, Any]:
        """Record outcome receipt for an externally executed crossing with bound claim."""
        dec_rec = self.boundary.receipt_store.get_decision_receipt(crossing_id)
        if dec_rec is None:
            return {
                "error": f"Decision receipt not found for crossing '{crossing_id}'",
                "code": "not_found",
            }

        existing_outcome = self.boundary.receipt_store.get_outcome_receipt(crossing_id)
        if existing_outcome is not None:
            return {
                "error": f"Outcome already recorded for crossing '{crossing_id}'",
                "code": "conflict",
            }

        if dec_rec.verdict not in ("allow", "allow_with_constraints"):
            p = self.boundary.receipt_store.get_pending_approval(crossing_id)
            if p is None or p.status != "approved":
                return {
                    "error": (
                        f"Cannot record execution outcome for non-allowed decision "
                        f"(crossing_id={crossing_id}, verdict={dec_rec.verdict})"
                    ),
                    "code": "not_permitted",
                }

        raw_env = self.boundary.receipt_store.get_envelope(crossing_id)
        if raw_env is None:
            return {"error": f"Crossing '{crossing_id}' not found in store", "code": "not_found"}

        # Inspect decision constraints by reconstructing envelope and evaluating
        dec_constraints: dict[str, Any] = {}
        try:
            action_data = raw_env.get("action") or {}
            agent_data = raw_env.get("agent") or {}
            prov_items = [
                ProvenanceItem(source=item["source"], trust=item["trust"])
                for item in raw_env.get("provenance", [])
                if isinstance(item, dict) and "source" in item and "trust" in item
            ]
            env = build_envelope(
                tool=str(action_data.get("tool", "")),
                verb=str(action_data.get("verb", "other")),
                resource=str(action_data.get("resource", "")),
                params=action_data.get("params") or {},
                session_id=str(raw_env.get("session_id", "default")),
                agent_id=str(agent_data.get("id", "http-client")),
                provenance=prov_items,
                crossing_id=crossing_id,
            )
            eval_dec = self.boundary.engine.evaluate(env)
            dec_constraints = dict(eval_dec.constraints)
        except Exception:
            dec_constraints = {}

        executor_principal = "anonymous_executor"
        if caller_context is not None:
            self._validate_caller_context(caller_context)
            if not caller_context.has_scope("crossings:outcome") and not caller_context.has_scope(
                "crossings:execute"
            ):
                return {
                    "error": (
                        f"Principal '{caller_context.principal_id}' lacks "
                        "'crossings:outcome' or 'crossings:execute' scope"
                    ),
                    "code": "forbidden",
                }
            executor_principal = caller_context.principal_id

        require_post = bool(
            dec_constraints.get("require_postcondition")
            or "postcondition" in dec_constraints
            or "required_postconditions" in dec_constraints
            or dec_constraints.get("strict_postconditions")
        )

        clean_claim_id = str(claim_id).strip() if claim_id is not None else None
        if not clean_claim_id and (
            caller_context is not None
            or require_claim
            or require_post
            or dec_constraints.get("require_claim")
        ):
            return {
                "error": (
                    "Missing required 'claim_id': external outcome reporting requires a valid "
                    "one-time execution claim issued via POST /v1/crossings/{id}/claim"
                ),
                "code": "claim_required",
            }

        # Phase 2: Strict bound observation verification before consuming claim
        consumed_obs: ObservationRecord | None = None
        if status == "success" and require_post:
            assert clean_claim_id is not None
            claim_rec = self.boundary.receipt_store.get_execution_claim(clean_claim_id)
            if claim_rec is None:
                return {
                    "error": f"Execution claim '{clean_claim_id}' not found",
                    "code": "not_found",
                }
            if claim_rec.crossing_id != crossing_id:
                return {
                    "error": (
                        f"Execution claim '{clean_claim_id}' was issued for crossing "
                        f"'{claim_rec.crossing_id}', not '{crossing_id}'"
                    ),
                    "code": "claim_invalid",
                }
            if claim_rec.canonical_hash != raw_env["canonical_hash"]:
                return {
                    "error": (
                        f"Execution claim '{clean_claim_id}' action hash mismatch "
                        f"for crossing '{crossing_id}'"
                    ),
                    "code": "claim_invalid",
                }
            if (
                executor_principal != "anonymous_executor"
                and claim_rec.executor_principal_id != executor_principal
            ):
                return {
                    "error": (
                        f"Execution claim '{clean_claim_id}' was issued to executor "
                        f"'{claim_rec.executor_principal_id}', not caller '{executor_principal}'"
                    ),
                    "code": "forbidden",
                }
            if claim_rec.status == "consumed":
                return {
                    "error": f"Execution claim '{clean_claim_id}' has already been consumed",
                    "code": "conflict",
                }
            if claim_rec.is_expired():
                return {
                    "error": f"Execution claim '{clean_claim_id}' has expired",
                    "code": "expired",
                }

            try:
                auth_resource, exp_claim, exp_digest = self._resolve_crossing_postcondition(
                    raw_env, dec_constraints
                )
            except Exception as exc:
                return {
                    "error": f"Invalid crossing postcondition specification: {exc}",
                    "code": "unverified_postcondition",
                }

            candidates: list[ObservationRecord] = []
            if observation_id:
                obs_id_clean = str(observation_id).strip()
                single_obs = self.boundary.receipt_store.get_observation(obs_id_clean)
                if single_obs is not None:
                    candidates = [single_obs]
            else:
                candidates = self.boundary.receipt_store.list_observations(crossing_id=crossing_id)

            matched_obs: ObservationRecord | None = None
            rejection_reasons: list[str] = []
            for cand in candidates:
                reason = self._validate_bound_observation_for_outcome(
                    cand,
                    crossing_id=crossing_id,
                    claim_id=clean_claim_id,
                    executor_principal_id=claim_rec.executor_principal_id,
                    canonical_action_hash=raw_env["canonical_hash"],
                    authorized_resource=auth_resource,
                    expected_claim=exp_claim,
                    expected_digest=exp_digest,
                    policy_version=dec_rec.policy_version,
                )
                if reason is None:
                    matched_obs = cand
                    break
                rejection_reasons.append(reason)

            if matched_obs is None:
                detail = (
                    rejection_reasons[0]
                    if rejection_reasons
                    else "no bound verified state observation was found"
                )
                return {
                    "error": (
                        f"False success promotion rejected: crossing '{crossing_id}' requires "
                        f"independent postcondition verification ({detail})"
                    ),
                    "code": "unverified_postcondition",
                }

            try:
                consumed_obs = self.boundary.receipt_store.consume_observation_for_outcome(
                    matched_obs.observation_id,
                    crossing_id=crossing_id,
                    claim_id=clean_claim_id,
                )
            except ObservationError as exc:
                err_low = str(exc).lower()
                code = (
                    "conflict"
                    if "consumed" in err_low or "replayed" in err_low
                    else "unverified_postcondition"
                )
                return {
                    "error": f"False success promotion rejected: {exc}",
                    "code": code,
                }

        # Validate and consume execution claim (Finding 5 & Phase 5)
        if clean_claim_id:
            try:
                self.boundary.receipt_store.consume_execution_claim(
                    clean_claim_id,
                    executor_principal_id=executor_principal,
                    crossing_id=crossing_id,
                    canonical_hash=raw_env["canonical_hash"],
                    result_digest=result_hash,
                    evidence_id=consumed_obs.observation_id if consumed_obs else None,
                    verification_status="verified" if consumed_obs else "unverified",
                )
            except ExecutionClaimError as exc:
                err_msg = str(exc)
                code = "claim_invalid"
                if "not found" in err_msg.lower():
                    code = "not_found"
                elif "caller" in err_msg.lower() or "executor" in err_msg.lower():
                    code = "forbidden"
                elif "replayed" in err_msg.lower() or "consumed" in err_msg.lower():
                    code = "conflict"
                elif "expired" in err_msg.lower():
                    code = "expired"
                return {"error": err_msg, "code": code}
        else:
            # Direct in-process call without caller_context and claim: auto-issue internal claim
            try:
                internal_claim = self.boundary.receipt_store.issue_execution_claim(
                    crossing_id=crossing_id,
                    executor_principal_id=executor_principal,
                    session_id=raw_env["session_id"],
                    canonical_hash=raw_env["canonical_hash"],
                )
                self.boundary.receipt_store.consume_execution_claim(
                    internal_claim.claim_id,
                    executor_principal_id=executor_principal,
                    crossing_id=crossing_id,
                    canonical_hash=raw_env["canonical_hash"],
                    result_digest=result_hash,
                )
                clean_claim_id = internal_claim.claim_id
            except ExecutionClaimError as exc:
                return {
                    "error": (
                        f"Outcome already recorded for crossing '{crossing_id}' "
                        f"(claim constraint: {exc})"
                    ),
                    "code": "conflict",
                }

        ev_status = "externally_verified" if consumed_obs is not None else "caller_reported"
        outcome_reason = "postcondition_verified" if consumed_obs is not None else "caller-reported"
        try:
            rec = self.boundary.receipt_store.record_outcome(
                crossing_id=crossing_id,
                session_id=raw_env["session_id"],
                canonical_hash=raw_env["canonical_hash"],
                policy_version=self.boundary.engine.policy.policy_version,
                status=status,
                result_hash=result_hash,
                error=error,
                reason=outcome_reason,
                evidence_status=ev_status,
                observation=consumed_obs,
            )
        except Exception as exc:
            code = "conflict" if "already recorded" in str(exc).lower() else "record_failed"
            return {"error": str(exc), "code": code}

        with contextlib.suppress(Exception):
            ev = build_evidence_record(
                crossing_id=crossing_id,
                tier=(
                    EvidenceTier.EXTERNALLY_VERIFIED
                    if consumed_obs is not None
                    else EvidenceTier.CALLER_REPORTED
                ),
                trust_domain=(
                    "verifier:workspace" if consumed_obs is not None else "external_caller"
                ),
                collector=(
                    consumed_obs.verifier_id
                    if consumed_obs is not None
                    else f"executor:{executor_principal}"
                ),
                details={
                    "claim_id": clean_claim_id,
                    "reported_status": status,
                    "result_hash": result_hash,
                    "error": error,
                    "executor_principal_id": executor_principal,
                    "observation_id": consumed_obs.observation_id if consumed_obs else None,
                    "verification_id": consumed_obs.verification_id if consumed_obs else None,
                    "verification_context_hash": (
                        consumed_obs.verification_context_hash if consumed_obs else None
                    ),
                },
            )
            self.boundary.receipt_store.record_evidence(ev)

        # Update session cumulative budgets for successful external execution
        if status == "success":
            action_data = raw_env.get("action") or {}
            agent_data = raw_env.get("agent") or {}
            prov_items = [
                ProvenanceItem(source=item["source"], trust=item["trust"])
                for item in raw_env.get("provenance", [])
                if isinstance(item, dict) and "source" in item and "trust" in item
            ]
            with contextlib.suppress(Exception):
                env = build_envelope(
                    tool=str(action_data.get("tool", "")),
                    verb=str(action_data.get("verb", "other")),
                    resource=str(action_data.get("resource", "")),
                    params=action_data.get("params") or {},
                    session_id=str(raw_env.get("session_id", "default")),
                    agent_id=str(agent_data.get("id", "http-client")),
                    provenance=prov_items,
                    crossing_id=crossing_id,
                )
                self.boundary.engine.budget_tracker.record_usage(
                    env,
                    principal_id=executor_principal,
                )

        resp: dict[str, Any] = {
            "status": "recorded",
            "crossing_id": crossing_id,
            "claim_id": clean_claim_id,
            "outcome_seq": rec.seq,
            "entry_hash": rec.entry_hash,
            "reported_by": "caller",
            "evidence_tier": ev_status,
            "externally_verified": consumed_obs is not None,
        }
        if consumed_obs is not None:
            resp["observation_id"] = consumed_obs.observation_id
            resp["verification_id"] = consumed_obs.verification_id
            resp["verification_context_hash"] = consumed_obs.verification_context_hash
        return resp

    # --- 4. Policy, Linting, & Canary ---

    def get_policy_yaml(self, caller_context: CallerContext | None = None) -> str:
        """Return the current active policy formatted as YAML."""
        self._require_scope_or_operator(caller_context, "policies:read")
        pack = self.boundary.engine.policy
        limits_list: list[dict[str, Any]] = [
            {"id": lim.id, "scope": lim.scope, "max_actions_per_minute": lim.max_actions_per_minute}
            for lim in pack.limits
        ]
        doc: dict[str, Any] = {
            "version": pack.version,
            "policy_id": pack.policy_id,
            "mode": pack.mode,
            "defaults": {
                "verdict": pack.default_verdict.value,
                "reason": pack.default_reason,
            },
        }
        if limits_list:
            doc["limits"] = limits_list
        if pack.budgets is not None:
            budgets_dict: dict[str, Any] = {}
            if pack.budgets.max_actions is not None:
                budgets_dict["max_actions"] = pack.budgets.max_actions
            if pack.budgets.max_external_calls is not None:
                budgets_dict["max_external_calls"] = pack.budgets.max_external_calls
            if pack.budgets.max_write_bytes is not None:
                budgets_dict["max_write_bytes"] = pack.budgets.max_write_bytes
            if pack.budgets.on_exceeded != Verdict.ASK:
                budgets_dict["on_exceeded"] = pack.budgets.on_exceeded.value
            if budgets_dict:
                doc["budgets"] = budgets_dict

        rules_list: list[dict[str, Any]] = []
        for r in pack.rules:
            match_dict: dict[str, Any] = {}
            if r.match.tool:
                match_dict["tool"] = r.match.tool
            if r.match.verbs:
                match_dict["verb"] = (
                    list(r.match.verbs) if len(r.match.verbs) > 1 else r.match.verbs[0]
                )
            if r.match.resource:
                match_dict["resource"] = r.match.resource
            if r.match.agent_id:
                match_dict["agent_id"] = r.match.agent_id
            if r.match.taint:
                match_dict["taint"] = r.match.taint
            if r.match.risk_any:
                match_dict["risk_any"] = list(r.match.risk_any)
            if r.match.risk_all:
                match_dict["risk_all"] = list(r.match.risk_all)

            item: dict[str, Any] = {
                "id": r.id,
                "match": match_dict,
                "verdict": r.verdict.value,
            }
            if r.reason:
                item["reason"] = r.reason
            if r.constraints:
                item["constraints"] = dict(r.constraints)
            rules_list.append(item)

        doc["rules"] = rules_list
        import yaml

        return yaml.dump(doc, sort_keys=False)

    def lint_active_policy(
        self, caller_context: CallerContext | None = None
    ) -> list[dict[str, str]]:
        """Run policy linter on the active policy pack."""
        self._require_scope_or_operator(caller_context, "policies:lint", "policies:read")
        warnings = lint_policy(self.boundary.engine.policy)
        return [{"message": w} for w in warnings]

    def run_canary_on_candidate(self, candidate_yaml: str, limit: int = 100) -> dict[str, Any]:
        """Run policy canary simulation against candidate YAML string."""
        from actentra_core.canary import run_policy_canary

        cand_policy = load_policy_yaml(candidate_yaml)
        db_path = self.boundary.receipt_store.db_path
        summary = run_policy_canary(cand_policy, db_path, limit=limit)
        return summary.to_dict()

    def simulate_dry_run(
        self,
        *,
        tool: str,
        verb: str,
        resource: str,
        params: dict[str, Any] | None = None,
        session_id: str = "default",
        provenance: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Simulate action evaluation without executing (dry-run)."""
        prov_items = [
            ProvenanceItem(source=p["source"], trust=p["trust"])  # type: ignore[arg-type]
            for p in (provenance or [])
            if "source" in p and "trust" in p
        ]
        decision = self.boundary.dry_run(
            tool=tool,
            verb=verb,
            resource=resource,
            params=params or {},
            session_id=session_id,
            provenance=prov_items,
            record_receipt=False,
        )
        return decision.to_dict()

    # --- 5. Receipts & Audit ---

    def query_receipts(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        verdict: str | None = None,
        tool: str | None = None,
        status: str | None = None,
        session_id: str | None = None,
        record_type: str | None = None,
        search: str | None = None,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any]:
        """Query bounded receipts with pagination and total count."""
        self._require_scope_or_operator(caller_context, "receipts:read")
        if (
            caller_context is not None
            and not caller_context.is_trusted_operator
            and not caller_context.has_scope("receipts:read_all")
            and session_id
        ):
            sess = self.boundary.receipt_store.get_session(session_id)
            auth_id = caller_context.authenticated_identity.lower()
            if sess and sess.principal_id.lower() != auth_id:
                raise IdentitySecurityError(
                    f"Principal '{caller_context.principal_id}' cannot access receipts "
                    f"for session '{session_id}' owned by '{sess.principal_id}'"
                )

        records, total = self.boundary.receipt_store.query_records(
            limit=limit,
            offset=offset,
            verdict=verdict,
            tool=tool,
            status=status,
            session_id=session_id,
            record_type=record_type,
            search=search,
        )

        # Object-level filtering for non-operator callers
        if (
            caller_context is not None
            and not caller_context.is_trusted_operator
            and not caller_context.has_scope("receipts:read_all")
        ):
            filtered_records = []
            auth_id = caller_context.authenticated_identity.lower()
            for r in records:
                sess = (
                    self.boundary.receipt_store.get_session(r.session_id) if r.session_id else None
                )
                if (
                    sess and sess.principal_id.lower() == auth_id
                ) or caller_context.is_agent_allowed(r.session_id):
                    filtered_records.append(r)
            records = filtered_records
            total = len(records)

        return {
            "records": [r.to_dict() for r in records],
            "total_count": total,
            "limit": limit,
            "offset": offset,
        }

    def verify_audit_log(
        self,
        *,
        verify_envelopes: bool = True,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any]:
        """Verify receipt log hash-chain and envelope integrity."""
        self._require_scope_or_operator(caller_context, "audit:verify", "receipts:read")
        vr = verify_log(self.boundary.receipt_store.db_path, verify_envelopes=verify_envelopes)
        return {
            "ok": vr.ok,
            "total_records": vr.total_records,
            "last_hash": vr.last_hash,
            "errors": list(vr.errors),
        }

    def export_audit_bundle(
        self,
        out_path: str | Path | None = None,
        caller_context: CallerContext | None = None,
        *,
        checkpoint_anchor: CheckpointAnchor | None = None,
        key_ring: KeyRing | None = None,
    ) -> dict[str, Any]:
        """Create an exportable offline audit bundle."""
        self._require_scope_or_operator(caller_context, "audit:export")
        vr = verify_log(self.boundary.receipt_store.db_path)
        records = [r.to_dict() for r in self.boundary.receipt_store.iter_records()]

        # Collect external checkpoints if anchor is provided or configured
        anchor = checkpoint_anchor or self.checkpoint_anchor
        external_cps = [cp.to_dict() for cp in anchor.list_checkpoints()] if anchor else []

        # Collect key rotation manifest if key ring is provided or configured
        ring = key_ring or self.key_ring
        key_manifest = ring.to_dict() if ring else {}

        bundle = {
            "actentra_version": "0.1.0a0",
            "export_ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "policy": {
                "id": self.boundary.engine.policy.policy_id,
                "version": self.boundary.engine.policy.policy_version,
                "yaml": self.get_policy_yaml(),
            },
            "integrity": {
                "ok": vr.ok,
                "total_records": vr.total_records,
                "head_hash": vr.last_hash,
                "errors": list(vr.errors),
            },
            "receipts": records,
            "external_checkpoints": external_cps,
            "key_manifest": key_manifest,
            "observations": [
                obs.to_dict() for obs in self.boundary.receipt_store.list_observations(limit=500)
            ],
            "causal_links": [
                lnk.to_dict() for lnk in self.boundary.receipt_store.list_causal_links(limit=500)
            ],
            "task_handoffs": [
                hnd.to_dict() for hnd in self.boundary.receipt_store.list_handoffs(limit=500)
            ],
            "evidence_records": [
                ev.to_dict() for ev in self.boundary.receipt_store.list_evidence(limit=500)
            ],
            "resource_leases": [
                lease.to_dict() for lease in self.boundary.receipt_store.list_leases(limit=500)
            ],
        }
        if out_path is not None:
            dest = Path(out_path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("w", encoding="utf-8") as fh:
                json.dump(bundle, fh, indent=2, ensure_ascii=False)
            bundle["exported_file"] = str(dest.resolve())
        return bundle

    # --- 8. State Observations (Phase 2) ---

    def verify_state(
        self,
        resource: str,
        claim: str,
        *,
        crossing_id: str | None = None,
        claim_id: str | None = None,
        expected_digest: str | None = None,
        ttl_seconds: float = 60.0,
        caller_context: CallerContext | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Perform a read-only state verification and persist a bound observation record."""
        try:
            self._require_scope_or_operator(caller_context, "observations:verify")
        except IdentitySecurityError as exc:
            return {"error": str(exc), "status": "error", "code": "forbidden"}

        if not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
            return {
                "error": f"ttl_seconds must be positive and finite, got {ttl_seconds!r}",
                "status": "error",
                "code": "invalid_ttl",
            }

        if self.file_verifier is None:
            return {
                "error": "No file verifier configured (register filesystem executor or verifier)",
                "status": "error",
            }

        if crossing_id is None:
            obs = self.file_verifier.verify(
                resource=resource,
                claim=claim,
                crossing_id=None,
                expected_digest=expected_digest,
                ttl_seconds=ttl_seconds,
                now=now,
            )
            self.boundary.receipt_store.record_observation(obs)
            return obs.to_dict()

        # --- Crossing-bound verification: establish canonical VerificationContext ---
        dec_rec = self.boundary.receipt_store.get_decision_receipt(crossing_id)
        if dec_rec is None:
            return {
                "error": f"Decision receipt not found for crossing '{crossing_id}'",
                "status": "error",
                "code": "not_found",
            }
        if dec_rec.verdict not in ("allow", "allow_with_constraints"):
            p = self.boundary.receipt_store.get_pending_approval(crossing_id)
            if p is None or p.status != "approved":
                return {
                    "error": (
                        f"Cannot verify crossing '{crossing_id}' with non-allowed decision "
                        f"(verdict={dec_rec.verdict})"
                    ),
                    "status": "error",
                    "code": "not_permitted",
                }
        if self.boundary.receipt_store.get_outcome_receipt(crossing_id) is not None:
            return {
                "error": f"Outcome already recorded for crossing '{crossing_id}'",
                "status": "error",
                "code": "conflict",
            }

        raw_env = self.boundary.receipt_store.get_envelope(crossing_id)
        if raw_env is None:
            return {
                "error": f"Crossing '{crossing_id}' envelope not found in store",
                "status": "error",
                "code": "not_found",
            }

        dec_constraints: dict[str, Any] = {}
        try:
            action_data = raw_env.get("action") or {}
            agent_data = raw_env.get("agent") or {}
            prov_items = [
                ProvenanceItem(source=item["source"], trust=item["trust"])
                for item in raw_env.get("provenance", [])
                if isinstance(item, dict) and "source" in item and "trust" in item
            ]
            env = build_envelope(
                tool=str(action_data.get("tool", "")),
                verb=str(action_data.get("verb", "other")),
                resource=str(action_data.get("resource", "")),
                params=action_data.get("params") or {},
                session_id=str(raw_env.get("session_id", "default")),
                agent_id=str(agent_data.get("id", "http-client")),
                provenance=prov_items,
                crossing_id=crossing_id,
            )
            dec_constraints = dict(self.boundary.engine.evaluate(env).constraints)
        except Exception:
            dec_constraints = {}

        try:
            auth_resource, exp_claim, exp_digest = self._resolve_crossing_postcondition(
                raw_env, dec_constraints
            )
        except Exception as exc:
            return {
                "error": f"Invalid crossing postcondition specification: {exc}",
                "status": "error",
                "code": "postcondition_mismatch",
            }

        try:
            req_resource = self._normalize_bound_resource(resource)
        except Exception as exc:
            return {
                "error": f"Invalid resource '{resource}': {exc}",
                "status": "error",
                "code": "resource_mismatch",
            }

        if req_resource != auth_resource:
            return {
                "error": (
                    f"Resource mismatch: requested '{req_resource}', but crossing "
                    f"'{crossing_id}' is authorized for '{auth_resource}'"
                ),
                "status": "error",
                "code": "resource_mismatch",
            }

        req_claim = canonicalize_unicode(claim).strip().lower()
        if req_claim != exp_claim:
            return {
                "error": (
                    f"Postcondition mismatch: requested '{req_claim}', but crossing "
                    f"'{crossing_id}' requires '{exp_claim}'"
                ),
                "status": "error",
                "code": "postcondition_mismatch",
            }

        req_digest = expected_digest.strip().lower() if expected_digest else None
        if exp_digest is not None and req_digest is not None and req_digest != exp_digest:
            return {
                "error": (
                    f"Expected digest mismatch: requested '{req_digest}', but crossing "
                    f"'{crossing_id}' requires '{exp_digest}'"
                ),
                "status": "error",
                "code": "digest_mismatch",
            }
        effective_digest = exp_digest if exp_digest is not None else req_digest
        if exp_claim == "digest_match" and not effective_digest:
            return {
                "error": f"Missing expected_digest for 'digest_match' on crossing '{crossing_id}'",
                "status": "error",
                "code": "missing_expected_digest",
            }

        # --- Execution claim binding ---
        if claim_id is not None and str(claim_id).strip():
            claim_rec = self.boundary.receipt_store.get_execution_claim(str(claim_id).strip())
            if claim_rec is None:
                return {
                    "error": f"Execution claim '{claim_id}' not found",
                    "status": "error",
                    "code": "claim_not_found",
                }
        else:
            claim_rec = self.boundary.receipt_store.get_execution_claim_for_crossing(crossing_id)
            if claim_rec is None:
                return {
                    "error": (
                        f"Crossing '{crossing_id}' must be claimed before bound state verification"
                    ),
                    "status": "error",
                    "code": "claim_required",
                }

        if claim_rec.crossing_id != crossing_id:
            return {
                "error": (
                    f"Execution claim '{claim_rec.claim_id}' belongs to crossing "
                    f"'{claim_rec.crossing_id}', not '{crossing_id}'"
                ),
                "status": "error",
                "code": "claim_crossing_mismatch",
            }
        if claim_rec.canonical_hash != raw_env["canonical_hash"]:
            return {
                "error": f"Execution claim '{claim_rec.claim_id}' canonical action hash mismatch",
                "status": "error",
                "code": "claim_action_mismatch",
            }
        if claim_rec.status != "issued":
            return {
                "error": (
                    f"Execution claim '{claim_rec.claim_id}' is not active "
                    f"(status={claim_rec.status})"
                ),
                "status": "error",
                "code": "claim_not_active",
            }
        if claim_rec.is_expired(now=now):
            return {
                "error": f"Execution claim '{claim_rec.claim_id}' has expired",
                "status": "error",
                "code": "claim_expired",
            }

        verifier_principal = (
            caller_context.principal_id if caller_context is not None else "local_verifier"
        )
        allowed_verifiers = dec_constraints.get("allowed_verifiers")
        if (
            isinstance(allowed_verifiers, (list, tuple, set))
            and allowed_verifiers
            and verifier_principal not in allowed_verifiers
        ):
            return {
                "error": (
                    f"Principal '{verifier_principal}' is not an authorized verifier "
                    f"for crossing '{crossing_id}'"
                ),
                "status": "error",
                "code": "forbidden",
            }

        ver_ctx = build_verification_context(
            crossing_id=crossing_id,
            canonical_action_hash=raw_env["canonical_hash"],
            authorized_resource=auth_resource,
            expected_postcondition=exp_claim,
            expected_digest=effective_digest,
            claim_id=claim_rec.claim_id,
            executor_principal_id=claim_rec.executor_principal_id,
            verifier_principal_id=verifier_principal,
            policy_version=dec_rec.policy_version,
            ttl_seconds=ttl_seconds,
            now=now,
        )

        raw_obs = self.file_verifier.verify(
            resource=auth_resource,
            claim=exp_claim,
            crossing_id=crossing_id,
            expected_digest=effective_digest,
            ttl_seconds=ttl_seconds,
            now=now,
        )
        obs = build_observation(
            observation_id=raw_obs.observation_id,
            subject_resource=raw_obs.subject_resource,
            claim=raw_obs.claim,
            status=raw_obs.status,
            verifier_id=raw_obs.verifier_id,
            verifier_version=raw_obs.verifier_version,
            trust_domain=raw_obs.trust_domain,
            observed_digest=raw_obs.observed_digest,
            metadata=raw_obs.metadata,
            error=raw_obs.error,
            verification_context=ver_ctx,
        )
        self.boundary.receipt_store.record_observation(obs)
        if obs.status == "verified":
            with contextlib.suppress(Exception):
                ev = build_evidence_record(
                    crossing_id=crossing_id,
                    tier=EvidenceTier.EXTERNALLY_VERIFIED,
                    trust_domain="verifier:workspace",
                    collector=obs.verifier_id,
                    details={
                        "observation_id": obs.observation_id,
                        "verification_id": obs.verification_id,
                        "claim_id": obs.claim_id,
                        "canonical_action_hash": obs.canonical_action_hash,
                        "resource": obs.subject_resource,
                        "claim": obs.claim,
                        "expected_digest": obs.expected_digest,
                        "observed_digest": obs.observed_digest,
                        "status": obs.status,
                        "executor_principal_id": obs.executor_principal_id,
                        "verifier_principal_id": obs.verifier_principal_id,
                        "policy_version": obs.policy_version,
                        "verification_context_hash": obs.verification_context_hash,
                    },
                    expires_at=obs.expires_at,
                )
                self.boundary.receipt_store.record_evidence(ev)
        return obs.to_dict()

    def get_observation(
        self,
        observation_id: str,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any] | None:
        """Fetch detail for a specific observation."""
        self._require_scope_or_operator(caller_context, "observations:read")
        obs = self.boundary.receipt_store.get_observation(observation_id)
        return obs.to_dict() if obs is not None else None

    def get_latest_observation(
        self,
        subject_resource: str,
        claim: str | None = None,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any] | None:
        """Fetch latest observation for a resource."""
        self._require_scope_or_operator(caller_context, "observations:read")
        obs = self.boundary.receipt_store.get_latest_observation(subject_resource, claim=claim)
        return obs.to_dict() if obs is not None else None

    def list_observations(
        self,
        *,
        crossing_id: str | None = None,
        subject_resource: str | None = None,
        limit: int = 50,
        offset: int = 0,
        caller_context: CallerContext | None = None,
    ) -> list[dict[str, Any]]:
        """List persisted observations."""
        self._require_scope_or_operator(caller_context, "observations:read")
        records = self.boundary.receipt_store.list_observations(
            crossing_id=crossing_id,
            subject_resource=subject_resource,
            limit=limit,
            offset=offset,
        )
        return [r.to_dict() for r in records]

    # --- Evidence Records Management (Phase 5) ---

    def get_evidence(
        self,
        evidence_id: str,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any] | None:
        """Fetch detail for a specific evidence record."""
        self._require_scope_or_operator(caller_context, "evidence:read")
        ev = self.boundary.receipt_store.get_evidence(evidence_id)
        return ev.to_dict() if ev is not None else None

    def list_evidence(
        self,
        *,
        crossing_id: str | None = None,
        tier: str | None = None,
        limit: int = 50,
        offset: int = 0,
        caller_context: CallerContext | None = None,
    ) -> list[dict[str, Any]]:
        """List persisted evidence records."""
        self._require_scope_or_operator(caller_context, "evidence:read")
        records = self.boundary.receipt_store.list_evidence(
            crossing_id=crossing_id,
            tier=tier,
            limit=limit,
            offset=offset,
        )
        return [r.to_dict() for r in records]

    # --- Causal Trace and Reference Links (Phase 3) ---

    def get_causal_trace(
        self,
        root_id: str,
        *,
        root_type: Literal["crossing", "observation", "task"] | None = None,
        max_depth: int = 10,
    ) -> dict[str, Any]:
        """Reconstruct the causal trace DAG and chronological timeline for an entity."""
        trace = build_causal_trace(
            self.boundary.receipt_store,
            root_id=root_id,
            root_type=root_type,
            max_depth=max_depth,
        )
        return trace.to_dict()

    def record_causal_link(
        self,
        *,
        source_id: str,
        source_type: Literal["crossing", "observation", "task"],
        relation: Literal["caused_by", "verifies", "derived_from", "triggers", "part_of"],
        target_id: str,
        target_type: Literal["crossing", "observation", "task"],
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create and persist an explicit directional causal relationship."""
        link = CausalLink(
            link_id=generate_link_id(),
            link_version="1",
            source_id=source_id,
            source_type=source_type,
            relation=relation,
            target_id=target_id,
            target_type=target_type,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            metadata=dict(metadata or {}),
        )
        saved = self.boundary.receipt_store.record_causal_link(link)
        return saved.to_dict()

    def list_causal_links(
        self,
        entity_id: str | None = None,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List causal links, optionally filtered by entity."""
        links = self.boundary.receipt_store.list_causal_links(entity_id=entity_id, limit=limit)
        return [lnk.to_dict() for lnk in links]

    def delete_causal_link(self, link_id: str) -> bool:
        """Delete an explicit causal link."""
        return self.boundary.receipt_store.delete_causal_link(link_id)

    # --- 10. Cross-Agent Continuity and Task Handoffs (Phase 4) ---

    def create_task_handoff(
        self,
        *,
        task_id: str,
        initiator_agent_id: str,
        assigned_agent_id: str,
        verifier_agent_id: str,
        allowed_verbs: list[str] | tuple[str, ...] = (),
        allowed_resources: list[str] | tuple[str, ...] = (),
        prior_crossings: list[str] | tuple[str, ...] = (),
        prior_observations: list[str] | tuple[str, ...] = (),
        assertions: dict[str, Any] | None = None,
        ttl_seconds: float = 3600.0,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any]:
        """Create a durable cross-agent task handoff record."""
        if caller_context is not None:
            self._validate_caller_context(caller_context)
            if not caller_context.has_scope("handoffs:create"):
                raise UnauthorizedAgentHandoffError(
                    f"Principal '{caller_context.principal_id}' lacks 'handoffs:create' scope"
                )
            if not caller_context.is_agent_allowed(initiator_agent_id):
                raise UnauthorizedAgentHandoffError(
                    f"Principal '{caller_context.principal_id}' is not authorized to "
                    f"initiate handoff as '{initiator_agent_id}'"
                )

        handoff = build_handoff(
            task_id=task_id,
            initiator_agent_id=initiator_agent_id,
            assigned_agent_id=assigned_agent_id,
            verifier_agent_id=verifier_agent_id,
            allowed_verbs=allowed_verbs,
            allowed_resources=allowed_resources,
            prior_crossings=prior_crossings,
            prior_observations=prior_observations,
            assertions=assertions,
            ttl_seconds=ttl_seconds,
        )
        saved = self.boundary.receipt_store.record_handoff(handoff)
        return saved.to_dict()

    def get_task_handoff(
        self,
        handoff_id: str,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any] | None:
        """Fetch detail for a specific task handoff (or active handoff by task_id)."""
        self._require_scope_or_operator(caller_context, "handoffs:read")
        hnd = self.boundary.receipt_store.get_handoff(handoff_id)
        if hnd is None:
            hnd = self.boundary.receipt_store.get_active_handoff_by_task(handoff_id)
        return hnd.to_dict() if hnd is not None else None

    def list_task_handoffs(
        self,
        *,
        task_id: str | None = None,
        assigned_agent_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        caller_context: CallerContext | None = None,
    ) -> list[dict[str, Any]]:
        """List task handoffs matching criteria."""
        self._require_scope_or_operator(caller_context, "handoffs:read")
        handoffs = self.boundary.receipt_store.list_handoffs(
            task_id=task_id,
            assigned_agent_id=assigned_agent_id,
            status=status,
            limit=limit,
        )
        return [h.to_dict() for h in handoffs]

    def advance_task_handoff(
        self,
        handoff_id: str,
        *,
        caller_agent_id: str,
        next_agent_id: str,
        crossing_id: str | None = None,
        observation_id: str | None = None,
        new_assertions: dict[str, Any] | None = None,
        allowed_verbs: list[str] | tuple[str, ...] | None = None,
        allowed_resources: list[str] | tuple[str, ...] | None = None,
        ttl_seconds: float = 3600.0,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any]:
        """Advance handoff to the next agent in the task workflow."""
        current = self.boundary.receipt_store.get_handoff(handoff_id)
        if current is None:
            raise HandoffError(f"Handoff '{handoff_id}' not found")

        if caller_context is not None:
            self._validate_caller_context(caller_context)
            if not caller_context.has_scope("handoffs:advance"):
                raise UnauthorizedAgentHandoffError(
                    f"Principal '{caller_context.principal_id}' lacks 'handoffs:advance' scope"
                )
            if not caller_context.is_agent_allowed(caller_agent_id):
                raise UnauthorizedAgentHandoffError(
                    f"Principal '{caller_context.principal_id}' is not authorized to "
                    f"advance handoff as '{caller_agent_id}'"
                )

        current.validate_caller(caller_agent_id)
        self.boundary.receipt_store.update_handoff_status(handoff_id, "completed")

        crossings = list(current.prior_crossings)
        if crossing_id and crossing_id not in crossings:
            crossings.append(crossing_id)

        observations = list(current.prior_observations)
        if observation_id and observation_id not in observations:
            observations.append(observation_id)

        merged_assertions = dict(current.assertions)
        if new_assertions:
            merged_assertions.update(new_assertions)

        next_verbs = allowed_verbs if allowed_verbs is not None else current.allowed_verbs
        next_resources = (
            allowed_resources if allowed_resources is not None else current.allowed_resources
        )

        next_handoff = build_handoff(
            task_id=current.task_id,
            initiator_agent_id=current.initiator_agent_id,
            assigned_agent_id=next_agent_id,
            verifier_agent_id=current.verifier_agent_id,
            allowed_verbs=next_verbs,
            allowed_resources=next_resources,
            prior_crossings=crossings,
            prior_observations=observations,
            assertions=merged_assertions,
            current_step=current.current_step + 1,
            ttl_seconds=ttl_seconds,
        )
        saved = self.boundary.receipt_store.record_handoff(next_handoff)

        with contextlib.suppress(Exception):
            self.record_causal_link(
                source_id=saved.handoff_id,
                source_type="task",
                relation="derived_from",
                target_id=current.handoff_id,
                target_type="task",
                metadata={"step": saved.current_step},
            )

        return saved.to_dict()

    def verify_task_handoff(
        self,
        handoff_id: str,
        *,
        verifier_agent_id: str,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any]:
        """Perform independent verification of handoff assertions using configured verifiers."""
        hnd = self.boundary.receipt_store.get_handoff(handoff_id)
        if hnd is None:
            raise HandoffError(f"Handoff '{handoff_id}' not found")

        if caller_context is not None:
            self._validate_caller_context(caller_context)
            if not caller_context.has_scope("handoffs:verify"):
                raise UnauthorizedAgentHandoffError(
                    f"Principal '{caller_context.principal_id}' lacks 'handoffs:verify' scope"
                )
            if not caller_context.is_agent_allowed(verifier_agent_id):
                raise UnauthorizedAgentHandoffError(
                    f"Principal '{caller_context.principal_id}' is not authorized to "
                    f"verify handoff as '{verifier_agent_id}'"
                )

        if verifier_agent_id != hnd.verifier_agent_id:
            raise UnauthorizedAgentHandoffError(
                f"Agent '{verifier_agent_id}' is not the designated verifier for handoff "
                f"'{handoff_id}'. Designated verifier is '{hnd.verifier_agent_id}'"
            )

        if not self.file_verifier:
            return {
                "error": "No verifier configured to inspect state assertions",
                "verified": False,
            }

        contradictions: list[str] = []
        observed_records: list[dict[str, Any]] = []

        assertions = hnd.assertions
        for res_key, claim_spec in assertions.items():
            expected_claim = (
                claim_spec.get("claim", "exists")
                if isinstance(claim_spec, dict)
                else str(claim_spec)
            )
            expected_digest = claim_spec.get("digest") if isinstance(claim_spec, dict) else None

            obs = self.file_verifier.verify(
                resource=res_key,
                claim=expected_claim,
                expected_digest=expected_digest,
                ttl_seconds=60.0,
            )
            self.boundary.receipt_store.record_observation(obs)
            observed_records.append(obs.to_dict())

            if obs.status != "verified":
                contradictions.append(
                    f"Assertion failed for {res_key}: expected '{expected_claim}', "
                    f"observed '{obs.status}' (error={obs.error})"
                )
            elif expected_digest and obs.observed_digest != expected_digest:
                contradictions.append(
                    f"Digest drift detected for {res_key}: expected {expected_digest}, "
                    f"observed {obs.observed_digest}"
                )

        if contradictions:
            self.boundary.receipt_store.update_handoff_status(
                handoff_id, "contradicted", contradictions=contradictions
            )
            return {
                "handoff_id": handoff_id,
                "task_id": hnd.task_id,
                "status": "contradicted",
                "verified": False,
                "contradictions": contradictions,
                "observations": observed_records,
            }

        self.boundary.receipt_store.update_handoff_status(handoff_id, "completed")
        return {
            "handoff_id": handoff_id,
            "task_id": hnd.task_id,
            "status": "completed",
            "verified": True,
            "contradictions": [],
            "observations": observed_records,
        }

    # --- 8. Multi-Agent Resource Coordination & Leases ---

    def acquire_resource_lease(
        self,
        resource: str,
        *,
        owner_agent_id: str,
        session_id: str,
        mode: LeaseMode = "exclusive",
        ttl_seconds: float = 60.0,
        metadata: dict[str, Any] | None = None,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any]:
        """Acquire a durable resource lease for an agent."""
        if caller_context is not None:
            try:
                self._validate_caller_context(caller_context)
            except IdentitySecurityError as exc:
                return {
                    "status": "error",
                    "error": str(exc),
                    "code": "unauthorized_principal",
                }
            if not caller_context.has_scope("leases:acquire"):
                return {
                    "status": "error",
                    "error": (
                        f"Principal '{caller_context.principal_id}' lacks 'leases:acquire' scope"
                    ),
                }
            if not caller_context.is_agent_allowed(owner_agent_id):
                return {
                    "status": "error",
                    "error": (
                        f"Principal '{caller_context.principal_id}' is not authorized to "
                        f"acquire lease for '{owner_agent_id}'"
                    ),
                }

        try:
            lease = build_lease(
                resource=resource,
                owner_agent_id=owner_agent_id,
                session_id=session_id,
                mode=mode,
                ttl_seconds=ttl_seconds,
                metadata=metadata,
            )
            saved = self.boundary.receipt_store.acquire_lease(lease)
            return {"status": "acquired", "lease": saved.to_dict()}
        except ResourceConflictError as exc:
            return {"status": "conflict", "error": str(exc)}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def release_resource_lease(
        self,
        lease_id: str,
        *,
        owner_agent_id: str | None = None,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any]:
        """Release an acquired resource lease."""
        if not owner_agent_id or not str(owner_agent_id).strip():
            return {
                "status": "not_found_or_unauthorized",
                "released": False,
                "error": "owner_agent_id is required to release lease",
            }

        if caller_context is not None:
            try:
                self._validate_caller_context(caller_context)
            except IdentitySecurityError as exc:
                return {
                    "status": "not_found_or_unauthorized",
                    "released": False,
                    "error": str(exc),
                    "code": "unauthorized_principal",
                }
            if not caller_context.has_scope("leases:release"):
                return {
                    "status": "not_found_or_unauthorized",
                    "released": False,
                    "error": (
                        f"Principal '{caller_context.principal_id}' lacks 'leases:release' scope"
                    ),
                }
            if not caller_context.is_agent_allowed(owner_agent_id):
                return {
                    "status": "not_found_or_unauthorized",
                    "released": False,
                    "error": (
                        f"Principal '{caller_context.principal_id}' is not authorized to "
                        f"release lease owned by '{owner_agent_id}'"
                    ),
                }

        released = self.boundary.receipt_store.release_lease(
            lease_id, owner_agent_id=str(owner_agent_id)
        )
        if not released:
            return {"status": "not_found_or_unauthorized", "released": False}
        return {"status": "released", "released": True, "lease_id": lease_id}

    def get_resource_lease(
        self,
        lease_id: str,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any] | None:
        """Get detail for a specific resource lease."""
        self._require_scope_or_operator(caller_context, "leases:read")
        lease = self.boundary.receipt_store.get_lease(lease_id)
        return lease.to_dict() if lease is not None else None

    def list_resource_leases(
        self,
        *,
        resource: str | None = None,
        owner_agent_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
        caller_context: CallerContext | None = None,
    ) -> list[dict[str, Any]]:
        """List resource leases with optional filtering."""
        self._require_scope_or_operator(caller_context, "leases:read")
        if (
            caller_context is not None
            and not caller_context.is_trusted_operator
            and owner_agent_id
            and not caller_context.is_agent_allowed(owner_agent_id)
        ):
            return []
        leases = self.boundary.receipt_store.list_leases(
            resource=resource,
            owner_agent_id=owner_agent_id,
            status=status,
            limit=limit,
            offset=offset,
        )
        return [lease_obj.to_dict() for lease_obj in leases]

    # --- 13. Explicit Delegation Authority ---

    def register_delegation(
        self,
        *,
        delegator_id: str,
        delegatee_id: str,
        allowed_agents: list[str] | tuple[str, ...],
        scopes: list[str] | tuple[str, ...],
        grant_id: str | None = None,
        ttl_seconds: float | None = None,
        audience: str | None = None,
        max_depth: int = 1,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any]:
        """Explicitly register an authorized delegation grant from delegator to delegatee."""
        if caller_context is not None:
            self._validate_caller_context(caller_context)
            if not caller_context.authenticated:
                raise IdentitySecurityError("Unauthenticated caller cannot delegate authority")
            if not caller_context.is_trusted_operator:
                if not caller_context.is_agent_allowed(delegator_id):
                    raise IdentitySecurityError(
                        f"Principal '{caller_context.principal_id}' is not authorized to "
                        f"delegate on behalf of '{delegator_id}'"
                    )
                for sc in scopes:
                    if not caller_context.has_scope(sc):
                        raise IdentitySecurityError(
                            f"Delegation scope violation: delegator "
                            f"'{caller_context.principal_id}' lacks scope '{sc}'"
                        )
                for ag in allowed_agents:
                    if not caller_context.is_agent_allowed(ag):
                        raise IdentitySecurityError(
                            f"Delegation agent violation: delegator "
                            f"'{caller_context.principal_id}' is not authorized for agent '{ag}'"
                        )
            delegator_ctx = caller_context
        else:
            delegator_ctx = make_local_caller_context(delegator_id)

        grant = self.delegation_registry.register_grant(
            delegator=delegator_ctx,
            delegatee_id=delegatee_id,
            allowed_agents=allowed_agents,
            scopes=scopes,
            grant_id=grant_id,
            ttl_seconds=ttl_seconds,
            audience=audience,
            max_depth=max_depth,
        )
        return grant.to_dict()

    def revoke_delegation(
        self,
        grant_id: str,
        caller_context: CallerContext | None = None,
    ) -> bool:
        """Revoke an active delegation grant."""
        if caller_context is not None:
            self._validate_caller_context(caller_context)
            revoker = caller_context
        else:
            revoker = make_local_caller_context("local_operator")
        return self.delegation_registry.revoke_grant(grant_id, revoker)

    def get_delegation(
        self,
        grant_id: str,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any] | None:
        """Fetch delegation grant by grant_id."""
        self._require_scope_or_operator(caller_context, "delegations:read")
        grant = self.delegation_registry.get_grant(grant_id)
        if grant is None:
            return None
        if caller_context is not None and not caller_context.is_trusted_operator:
            ident = caller_context.authenticated_identity.lower()
            if ident not in (grant.delegator_id.lower(), grant.delegatee_id.lower()):
                raise IdentitySecurityError(
                    f"Principal '{caller_context.principal_id}' not authorized "
                    f"to view delegation '{grant_id}'"
                )
        return grant.to_dict()

    # --- 14. Server-Controlled Session Management (Phase 2) ---

    def create_session_record(
        self,
        caller_context: CallerContext | None = None,
        trust_domain: str = "default",
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        ttl_seconds: float = 3600.0,
    ) -> SessionRecord:
        """Create a server-controlled session record bound to authenticated principal."""
        principal_id = caller_context.authenticated_identity if caller_context else "local_operator"
        if not session_id:
            session_id = f"sess-{uuid.uuid4().hex[:16]}"
        policy_version = self.boundary.engine.policy.policy_version
        return self.boundary.receipt_store.create_session(
            session_id=session_id,
            principal_id=principal_id,
            trust_domain=trust_domain,
            policy_version=policy_version,
            ttl_seconds=ttl_seconds,
            metadata=metadata,
        )

    def validate_session_access(
        self,
        session_id: str,
        caller_context: CallerContext | None = None,
        auto_create: bool = True,
    ) -> SessionRecord:
        """Validate that the caller is authorized to access the given session ID.

        If the session does not exist and auto_create is True, it is bound to the
        caller's authenticated identity. If the session exists and belongs to another
        principal, IdentitySecurityError is raised.
        """
        if caller_context is not None:
            self._validate_caller_context(caller_context)
            caller_principal = caller_context.authenticated_identity.lower()
        else:
            caller_principal = "local_operator"

        existing = self.boundary.receipt_store.get_session(session_id)
        if existing is None:
            if not auto_create:
                raise IdentitySecurityError(f"Session '{session_id}' not found or expired")
            policy_version = self.boundary.engine.policy.policy_version
            return self.boundary.receipt_store.create_session(
                session_id=session_id,
                principal_id=caller_principal,
                trust_domain="default",
                policy_version=policy_version,
                ttl_seconds=3600.0,
            )

        if existing.status == "revoked":
            raise IdentitySecurityError(f"Session '{session_id}' has been revoked")
        if existing.status == "expired":
            raise IdentitySecurityError(f"Session '{session_id}' has expired")

        if (
            caller_context is not None
            and not caller_context.is_trusted_operator
            and existing.principal_id.lower() != caller_principal
        ):
            raise IdentitySecurityError(
                f"Principal '{caller_context.principal_id}' cannot access session "
                f"'{session_id}' owned by '{existing.principal_id}'"
            )

        return existing

    def create_session(
        self,
        principal_id: str | None = None,
        trust_domain: str = "default",
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        ttl_seconds: float = 3600.0,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any]:
        """Create a server-controlled session record."""
        self._require_scope_or_operator(caller_context, "sessions:create")
        if caller_context is not None and not caller_context.is_trusted_operator:
            auth_id = caller_context.authenticated_identity.lower()
            if principal_id and principal_id.lower() != auth_id:
                raise IdentitySecurityError(
                    f"Principal '{caller_context.principal_id}' cannot create "
                    f"session for '{principal_id}'"
                )
            principal_id = caller_context.authenticated_identity
        else:
            if not principal_id:
                principal_id = "local_operator"

        target_principal = principal_id or "local_operator"
        if not session_id:
            session_id = f"sess-{uuid.uuid4().hex[:16]}"

        policy_version = self.boundary.engine.policy.policy_version
        rec = self.boundary.receipt_store.create_session(
            session_id=session_id,
            principal_id=target_principal,
            trust_domain=trust_domain,
            policy_version=policy_version,
            ttl_seconds=ttl_seconds,
            metadata=metadata,
        )
        return rec.to_dict()

    def get_session(
        self,
        session_id: str,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any] | None:
        """Fetch session detail by session_id, enforcing ownership check."""
        self._require_scope_or_operator(caller_context, "sessions:read")
        rec = self.boundary.receipt_store.get_session(session_id)
        if rec is None:
            return None

        if (
            caller_context is not None
            and not caller_context.is_trusted_operator
            and rec.principal_id.lower() != caller_context.authenticated_identity.lower()
        ):
            raise IdentitySecurityError(
                f"Principal '{caller_context.principal_id}' cannot read session '{session_id}' "
                f"owned by '{rec.principal_id}'"
            )
        return rec.to_dict()

    def list_sessions(
        self,
        principal_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
        caller_context: CallerContext | None = None,
    ) -> list[dict[str, Any]]:
        """List session records, partitioned by principal for non-operators."""
        self._require_scope_or_operator(caller_context, "sessions:read")
        if caller_context is not None and not caller_context.is_trusted_operator:
            principal_id = caller_context.authenticated_identity

        records = self.boundary.receipt_store.list_sessions(
            principal_id=principal_id,
            status=status,
            limit=limit,
            offset=offset,
        )
        return [r.to_dict() for r in records]

    def revoke_session(
        self,
        session_id: str,
        caller_context: CallerContext | None = None,
    ) -> bool:
        """Revoke a session."""
        self._require_scope_or_operator(caller_context, "sessions:revoke")
        if caller_context is not None and not caller_context.is_trusted_operator:
            existing = self.boundary.receipt_store.get_session(session_id)
            if (
                existing
                and existing.principal_id.lower() != caller_context.authenticated_identity.lower()
            ):
                raise IdentitySecurityError(
                    f"Principal '{caller_context.principal_id}' cannot revoke session "
                    f"'{session_id}' owned by '{existing.principal_id}'"
                )

        return self.boundary.receipt_store.revoke_session(session_id)

    def freeze(self, caller_context: CallerContext | None = None) -> None:
        """Freeze the boundary engine to block new crossings."""
        self._require_scope_or_operator(caller_context, "system:freeze")
        self.boundary.freeze()

    def unfreeze(self, caller_context: CallerContext | None = None) -> None:
        """Unfreeze the boundary engine."""
        self._require_scope_or_operator(caller_context, "system:unfreeze")
        self.boundary.unfreeze()

    def is_frozen(self) -> bool:
        """Check if boundary engine is frozen."""
        return self.boundary.is_frozen
