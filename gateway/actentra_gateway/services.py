"""Typed Application Services layer for Actentra.

Unifies core deterministic kernel, executors, persistent receipts, approvals,
canary simulations, and audit reporting for both the CLI and Local Web UI.
"""

from __future__ import annotations

import contextlib
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from actentra.boundary import ActionBlockedError, Boundary
from actentra_core.canonicalize import hash_canonical
from actentra_core.causal import (
    CausalLink,
    build_causal_trace,
    generate_link_id,
)
from actentra_core.coordination import (
    LeaseMode,
    ResourceConflictError,
    build_lease,
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
    IdentitySecurityError,
)
from actentra_core.policy import lint_policy, load_policy_yaml
from actentra_core.receipts import GENESIS_HASH, verify_log
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
    ) -> None:
        self.boundary = boundary
        self.registry = executor_registry or ExecutorRegistry()
        self.approval_ttl_seconds = approval_ttl_seconds
        if file_verifier is not None:
            self.file_verifier: WorkspaceFileVerifier | None = file_verifier
        elif self.registry.workspace_root is not None:
            self.file_verifier = WorkspaceFileVerifier(self.registry.workspace_root)
        else:
            self.file_verifier = None
        # Clean up expired approvals upon service startup (idempotent, restart-safe)
        self.boundary.receipt_store.recover_pending_approvals()

    # --- 1. Health & Status ---

    def get_health(self, *, full_verify: bool = False) -> dict[str, Any]:
        """Return runtime health, policy state, and receipt store integrity."""
        db_path = self.boundary.receipt_store.db_path
        pending_list = self.boundary.receipt_store.list_pending_approvals(status="pending")
        if full_verify:
            vr = verify_log(db_path, verify_envelopes=True)
            total_records = vr.total_records
            integrity_ok = vr.ok
            last_hash = vr.last_hash
        else:
            latest = self.boundary.receipt_store.get_latest_record()
            total_records = self.boundary.receipt_store.record_count()
            integrity_ok = True
            last_hash = latest.entry_hash if latest else GENESIS_HASH

        return {
            "status": "ok",
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

    # --- 2. Crossing Submission & Lifecycle ---

    def submit_crossing(
        self,
        data: dict[str, Any],
        *,
        execute: bool = False,
        caller_context: CallerContext | None = None,
    ) -> dict[str, Any]:
        """Propose, canonicalize, evaluate, and conditionally execute an action."""
        # Enforce authenticated identity and principal constraints (Stage 0 Task 2)
        raw_agent = data.get("agent_id")
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
            if not caller_context.has_scope("crossings:propose"):
                return {
                    "verdict": Verdict.DENY.value,
                    "error": (
                        f"Caller '{caller_context.principal_id}' lacks "
                        "scope 'crossings:propose'"
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
                        f"Caller '{caller_context.principal_id}' lacks "
                        "scope 'crossings:execute'"
                    ),
                    "code": "unauthorized_principal",
                    "rule_id": "identity:scope-denied",
                    "canonical_hash": "sha256:" + ("0" * 64),
                    "risk_tags": ["unauthorized-action"],
                }

        session_id = str(data.get("session_id", "default")).strip() or "default"
        if len(session_id) > 128:
            return {
                "verdict": Verdict.HOLD.value,
                "error": "session_id exceeds maximum length of 128 characters",
                "rule_id": "kernel:session-id-too-long",
                "canonical_hash": "sha256:" + ("0" * 64),
                "risk_tags": [],
            }
        prov_items = [
            ProvenanceItem(source=p["source"], trust=p["trust"])
            for p in data.get("provenance", [])
            if isinstance(p, dict) and "source" in p and "trust" in p
        ]
        # Propagate session taint across gateway crossings
        # (cannot be bypassed by declared provenance)
        if self.boundary.get_session_taint(session_id) == "untrusted" and not any(
            p.trust == "untrusted" for p in prov_items
        ):
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

        # Update session taint tracker if this action is untrusted (Finding 5)
        if envelope.max_taint == "untrusted":
            self.boundary.set_session_taint("untrusted", session_id=envelope.session_id)

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
                try:
                    exec_result = self._dispatch_and_record(envelope, decision, executor)
                    resp["executed"] = True
                    resp["outcome"] = {"status": "success", "result": exec_result}
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
    ) -> Any:
        """Internal dispatch executing the action and recording the outcome receipt."""
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

        try:
            result = executor(envelope, decision)
        except Exception as exc:
            err_label = type(exc).__name__
            if self.boundary.secrets_broker is not None:
                err_label = self.boundary.secrets_broker.redact(err_label)
            self.boundary.receipt_store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="failure",
                error=err_label,
                evidence_status="locally_observed",
            )
            raise

        res_hash: str | None = None
        try:
            res_hash = hash_canonical(result)
        except Exception:
            res_hash = None

        self.boundary.receipt_store.record_outcome(
            crossing_id=envelope.crossing_id,
            session_id=envelope.session_id,
            canonical_hash=envelope.canonical_hash,
            policy_version=decision.policy_version,
            status="success",
            result_hash=res_hash,
            evidence_status="locally_observed",
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
        # Update session cumulative budgets for gateway execution (Finding 6)
        self.boundary.engine.budget_tracker.record_usage(envelope)
        return result

    # --- 3. Approvals Management ---

    def list_pending_approvals(
        self,
        *,
        status: str | None = "pending",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List pending approvals from SQLite store."""
        records = self.boundary.receipt_store.list_pending_approvals(status=status, limit=limit)
        return [r.to_dict() for r in records]

    def get_pending_approval(self, crossing_id: str) -> dict[str, Any] | None:
        """Get detail for a specific crossing approval."""
        r = self.boundary.receipt_store.get_pending_approval(crossing_id)
        return r.to_dict() if r is not None else None

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

        res = self.boundary.receipt_store.resolve_pending_approval(crossing_id, approved=approved)
        if res is None:
            return {
                "error": f"Pending crossing '{crossing_id}' not found, already resolved, or expired"
            }

        if approved:
            self.boundary.grant_approval(
                canonical_hash=res.canonical_hash,
                session_id=res.session_id,
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
                        f"Principal '{caller_context.principal_id}' lacks "
                        "'crossings:execute' scope"
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
            result = self._dispatch_and_record(envelope, decision, executor)
            return {"status": "success", "result": result, "crossing_id": crossing_id}
        except Exception as exc:
            return {"status": "failure", "error": type(exc).__name__, "crossing_id": crossing_id}

    def record_external_outcome(
        self,
        crossing_id: str,
        *,
        status: Literal["success", "failure", "unknown"],
        result_hash: str | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        """Record outcome receipt for an externally executed crossing."""
        # Check corresponding decision receipt exists
        dec_rec = self.boundary.receipt_store.get_decision_receipt(crossing_id)
        if dec_rec is None:
            return {"error": f"Decision receipt not found for crossing '{crossing_id}'"}

        # Verify that the decision permitted execution
        if dec_rec.verdict not in ("allow", "allow_with_constraints"):
            return {
                "error": (
                    f"Cannot record execution outcome for non-allowed decision "
                    f"(crossing_id={crossing_id}, verdict={dec_rec.verdict})"
                )
            }

        raw_env = self.boundary.receipt_store.get_envelope(crossing_id)
        if raw_env is None:
            return {"error": f"Crossing '{crossing_id}' not found in store"}

        try:
            rec = self.boundary.receipt_store.record_outcome(
                crossing_id=crossing_id,
                session_id=raw_env["session_id"],
                canonical_hash=raw_env["canonical_hash"],
                policy_version=self.boundary.engine.policy.policy_version,
                status=status,
                result_hash=result_hash,
                error=error,
                reason="caller-reported",
                evidence_status="caller_reported",
            )
        except Exception as exc:
            return {"error": str(exc)}

        with contextlib.suppress(Exception):
            ev = build_evidence_record(
                crossing_id=crossing_id,
                tier=EvidenceTier.CALLER_REPORTED,
                trust_domain="external_caller",
                collector="http_client",
                details={"reported_status": status, "result_hash": result_hash, "error": error},
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
                self.boundary.engine.budget_tracker.record_usage(env)

        return {
            "status": "recorded",
            "outcome_seq": rec.seq,
            "entry_hash": rec.entry_hash,
            "reported_by": "caller",
            "evidence_tier": "caller_reported",
            "externally_verified": False,
        }

    # --- 4. Policy, Linting, & Canary ---

    def get_policy_yaml(self) -> str:
        """Return the current active policy formatted as YAML."""
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

    def lint_active_policy(self) -> list[dict[str, str]]:
        """Run policy linter on the active policy pack."""
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
    ) -> dict[str, Any]:
        """Query bounded receipts with pagination and total count."""
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
        return {
            "records": [r.to_dict() for r in records],
            "total_count": total,
            "limit": limit,
            "offset": offset,
        }

    def verify_audit_log(self, *, verify_envelopes: bool = True) -> dict[str, Any]:
        """Verify receipt log hash-chain and envelope integrity."""
        vr = verify_log(self.boundary.receipt_store.db_path, verify_envelopes=verify_envelopes)
        return {
            "ok": vr.ok,
            "total_records": vr.total_records,
            "last_hash": vr.last_hash,
            "errors": list(vr.errors),
        }

    def export_audit_bundle(self, out_path: str | Path | None = None) -> dict[str, Any]:
        """Create an exportable offline audit bundle."""
        vr = verify_log(self.boundary.receipt_store.db_path)
        records = [r.to_dict() for r in self.boundary.receipt_store.iter_records()]
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
        expected_digest: str | None = None,
        ttl_seconds: float = 60.0,
    ) -> dict[str, Any]:
        """Perform a read-only state verification and persist an observation record."""
        if self.file_verifier is None:
            return {
                "error": "No file verifier configured (register filesystem executor or verifier)",
                "status": "error",
            }
        obs = self.file_verifier.verify(
            resource=resource,
            claim=claim,
            crossing_id=crossing_id,
            expected_digest=expected_digest,
            ttl_seconds=ttl_seconds,
        )
        self.boundary.receipt_store.record_observation(obs)
        if obs.status == "verified" and crossing_id:
            with contextlib.suppress(Exception):
                ev = build_evidence_record(
                    crossing_id=crossing_id,
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
        return obs.to_dict()

    def get_observation(self, observation_id: str) -> dict[str, Any] | None:
        """Fetch detail for a specific observation."""
        obs = self.boundary.receipt_store.get_observation(observation_id)
        return obs.to_dict() if obs is not None else None

    def get_latest_observation(
        self,
        subject_resource: str,
        claim: str | None = None,
    ) -> dict[str, Any] | None:
        """Fetch latest observation for a resource."""
        obs = self.boundary.receipt_store.get_latest_observation(subject_resource, claim=claim)
        return obs.to_dict() if obs is not None else None

    def list_observations(
        self,
        *,
        crossing_id: str | None = None,
        subject_resource: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List persisted observations."""
        records = self.boundary.receipt_store.list_observations(
            crossing_id=crossing_id,
            subject_resource=subject_resource,
            limit=limit,
            offset=offset,
        )
        return [r.to_dict() for r in records]

    # --- Evidence Records Management (Phase 5) ---

    def get_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        """Fetch detail for a specific evidence record."""
        ev = self.boundary.receipt_store.get_evidence(evidence_id)
        return ev.to_dict() if ev is not None else None

    def list_evidence(
        self,
        *,
        crossing_id: str | None = None,
        tier: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List persisted evidence records."""
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

    def get_task_handoff(self, handoff_id: str) -> dict[str, Any] | None:
        """Fetch detail for a specific task handoff (or active handoff by task_id)."""
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
    ) -> list[dict[str, Any]]:
        """List task handoffs matching criteria."""
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
            if not caller_context.has_scope("leases:acquire"):
                return {
                    "status": "error",
                    "error": (
                        f"Principal '{caller_context.principal_id}' lacks "
                        "'leases:acquire' scope"
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
            if not caller_context.has_scope("leases:release"):
                return {
                    "status": "not_found_or_unauthorized",
                    "released": False,
                    "error": (
                        f"Principal '{caller_context.principal_id}' lacks "
                        "'leases:release' scope"
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

    def get_resource_lease(self, lease_id: str) -> dict[str, Any] | None:
        """Get detail for a specific resource lease."""
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
    ) -> list[dict[str, Any]]:
        """List resource leases with optional filtering."""
        leases = self.boundary.receipt_store.list_leases(
            resource=resource,
            owner_agent_id=owner_agent_id,
            status=status,
            limit=limit,
            offset=offset,
        )
        return [lease_obj.to_dict() for lease_obj in leases]
