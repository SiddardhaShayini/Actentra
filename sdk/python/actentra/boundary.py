"""In-process Python SDK for Actentra execution boundaries."""

from __future__ import annotations

import contextlib
import functools
import inspect
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, TypeVar, cast

from actentra.secrets import SecretsBroker
from actentra_core.canonicalize import CanonicalizationError, hash_canonical
from actentra_core.causal import CausalLink, generate_link_id
from actentra_core.coordination import (
    LeaseMode,
    ResourceLease,
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
from actentra_core.evidence import EvidenceTier, build_evidence_record
from actentra_core.identity import CallerContext
from actentra_core.observations import ObservationRecord, build_observation
from actentra_core.policy import PolicyEngine, PolicyPack, load_policy_file
from actentra_core.receipts import ReceiptError, ReceiptStore
from actentra_core.verdict import Decision, Verdict
from actentra_core.warrants import (
    Warrant,
    WarrantError,
    WarrantRegistry,
    is_action_permitted_by_warrant,
    verify_warrant,
)

F = TypeVar("F", bound=Callable[..., Any])
ApprovalCallback = Callable[[ActionEnvelope, Decision], bool]


class ActentraError(RuntimeError):
    """Base error raised by the Actentra SDK."""


class ActionBlockedError(ActentraError):
    """Raised when an action is blocked by policy (DENY, HOLD, or unapproved ASK)."""

    def __init__(self, decision: Decision, crossing_id: str) -> None:
        self.decision = decision
        self.crossing_id = crossing_id
        super().__init__(
            f"[{decision.verdict.value.upper()}] rule={decision.rule_id} "
            f"crossing={crossing_id}: {decision.reason}"
        )


class PostconditionFailedError(ActentraError):
    """Raised when an action's postcondition fails verification (refuted, error, or unverified)."""

    def __init__(
        self,
        observation: ObservationRecord | None,
        outcome_status: str,
        message: str,
    ) -> None:
        self.observation = observation
        self.outcome_status = outcome_status
        super().__init__(message)


class ApprovalGrant:
    """One-session, hash-bound, expiring human approval (Invariant I4)."""

    __slots__ = ("canonical_hash", "session_id", "expires_at")

    def __init__(self, canonical_hash: str, session_id: str, expires_at: float) -> None:
        self.canonical_hash = canonical_hash
        self.session_id = session_id
        self.expires_at = expires_at


def cli_approval_prompt(envelope: ActionEnvelope, decision: Decision) -> bool:
    """Interactive terminal prompt for ASK verdicts (V1 CLI approval)."""
    print("\n=== Actentra Approval Required ===")
    print(f"Crossing : {envelope.crossing_id}")
    print(f"Session  : {envelope.session_id}")
    print(f"Agent    : {envelope.agent.id}")
    print(f"Tool     : {envelope.action.tool} ({envelope.action.verb})")
    print(f"Resource : {envelope.action.resource}")
    print(f"Hash     : {envelope.canonical_hash}")
    print(f"Risk     : {', '.join(decision.risk_tags) or 'none'}")
    print(f"Rule     : {decision.rule_id} — {decision.reason}")
    try:
        answer = input("Approve exact action hash? [y/N]: ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


class Boundary:
    """Local-first execution boundary mediating tool calls against policy and receipts."""

    def __init__(
        self,
        *,
        policy: PolicyPack,
        receipt_store: ReceiptStore,
        session_id: str = "default",
        agent_id: str = "default-agent",
        framework: str = "python-sdk",
        model: str = "unknown",
        approval_callback: ApprovalCallback | None = None,
        approval_ttl_seconds: float = 300.0,
        secrets_broker: SecretsBroker | None = None,
        warrant_public_key: bytes | None = None,
        warrant_registry: WarrantRegistry | None = None,
        verifier: Any | None = None,
        caller_context: CallerContext | None = None,
    ) -> None:
        self._engine = PolicyEngine(policy)
        self._store = receipt_store
        self._engine.budget_tracker.set_receipt_store(self._store)
        self._session_id = session_id
        self._agent_id = agent_id
        self._framework = framework
        self._model = model
        self._approval_callback = approval_callback
        self._approval_ttl = approval_ttl_seconds
        self._secrets_broker = secrets_broker
        self._warrant_public_key = warrant_public_key
        self._caller_context = caller_context
        if warrant_registry is not None:
            self._warrant_registry = warrant_registry
            if self._warrant_registry.receipt_store is None:
                self._warrant_registry.set_receipt_store(self._store)
        else:
            self._warrant_registry = WarrantRegistry(receipt_store=self._store)
        self._engine.budget_tracker.set_receipt_store(self._store)
        self._verifier = verifier
        self._lock = threading.Lock()
        self._approvals: dict[tuple[str, str], ApprovalGrant] = {}
        self._session_taints: dict[str, str] = {}

    @classmethod
    def from_files(
        cls,
        *,
        policy_path: str | Path,
        receipts_db: str | Path,
        session_id: str = "default",
        agent_id: str = "default-agent",
        approval_callback: ApprovalCallback | None = None,
        secrets_broker: SecretsBroker | None = None,
        warrant_public_key: bytes | None = None,
        warrant_registry: WarrantRegistry | None = None,
        verifier: Any | None = None,
        caller_context: CallerContext | None = None,
    ) -> Boundary:
        policy = load_policy_file(policy_path)
        store = ReceiptStore(receipts_db)
        return cls(
            policy=policy,
            receipt_store=store,
            session_id=session_id,
            agent_id=agent_id,
            approval_callback=approval_callback,
            secrets_broker=secrets_broker,
            warrant_public_key=warrant_public_key,
            warrant_registry=warrant_registry,
            verifier=verifier,
            caller_context=caller_context,
        )

    @property
    def engine(self) -> PolicyEngine:
        return self._engine

    @property
    def receipt_store(self) -> ReceiptStore:
        return self._store

    @property
    def verifier(self) -> Any | None:
        return self._verifier

    @property
    def secrets_broker(self) -> SecretsBroker | None:
        return self._secrets_broker

    @property
    def warrant_public_key(self) -> bytes | None:
        return self._warrant_public_key

    @property
    def warrant_registry(self) -> WarrantRegistry | None:
        return self._warrant_registry

    def _check_warrant(
        self,
        warrant: Warrant | dict[str, Any] | None,
        *,
        tool: str,
        resource: str,
        effective_agent: str,
    ) -> Warrant | None:
        if warrant is None:
            return None

        warrant_obj: Warrant
        if isinstance(warrant, dict):
            try:
                warrant_obj = Warrant.from_dict(warrant)
            except Exception as exc:
                hold_decision = Decision(
                    verdict=Verdict.HOLD,
                    rule_id="warrant:malformed",
                    reason=f"Warrant dictionary malformed: {exc}",
                    policy_version=self._engine.policy.policy_version,
                    canonical_hash="sha256:" + ("0" * 64),
                )
                raise ActionBlockedError(hold_decision, "INVALID_WARRANT") from exc
        elif isinstance(warrant, Warrant):
            warrant_obj = warrant
        else:
            hold_decision = Decision(
                verdict=Verdict.HOLD,
                rule_id="warrant:malformed",
                reason=f"Unsupported warrant type: {type(warrant).__name__}",
                policy_version=self._engine.policy.policy_version,
                canonical_hash="sha256:" + ("0" * 64),
            )
            raise ActionBlockedError(hold_decision, "INVALID_WARRANT")

        if self._warrant_public_key is not None:
            valid, msg = verify_warrant(
                warrant_obj,
                self._warrant_public_key,
                expected_holder=effective_agent,
            )
            if not valid:
                deny_decision = Decision(
                    verdict=Verdict.DENY,
                    rule_id="warrant:invalid",
                    reason=f"Warrant cryptographic verification failed: {msg}",
                    policy_version=self._engine.policy.policy_version,
                    canonical_hash="sha256:" + ("0" * 64),
                )
                raise ActionBlockedError(deny_decision, "WARRANT_REJECTED")

        if not is_action_permitted_by_warrant(warrant_obj, tool=tool, resource=resource):
            deny_decision = Decision(
                verdict=Verdict.DENY,
                rule_id="warrant:scope-denied",
                reason=(
                    f"Action '{tool}' on '{resource}' is not authorized by warrant "
                    f"'{warrant_obj.warrant_id}'"
                ),
                policy_version=self._engine.policy.policy_version,
                canonical_hash="sha256:" + ("0" * 64),
            )
            raise ActionBlockedError(deny_decision, "WARRANT_SCOPE_DENIED")

        if self._warrant_registry is not None:
            rem = self._warrant_registry.remaining_uses(warrant_obj)
            if rem is not None and rem <= 0:
                deny_decision = Decision(
                    verdict=Verdict.DENY,
                    rule_id="warrant:exhausted",
                    reason=(
                        f"Warrant '{warrant_obj.warrant_id}' max uses "
                        f"({warrant_obj.max_uses}) exceeded"
                    ),
                    policy_version=self._engine.policy.policy_version,
                    canonical_hash="sha256:" + ("0" * 64),
                )
                raise ActionBlockedError(deny_decision, "WARRANT_EXHAUSTED")

        return warrant_obj

    def freeze(self) -> None:
        self._engine.freeze()

    def unfreeze(self) -> None:
        self._engine.unfreeze()

    @property
    def is_frozen(self) -> bool:
        return bool(self._engine.frozen)

    def _has_valid_approval(self, envelope: ActionEnvelope) -> bool:
        with self._lock:
            key = (envelope.session_id, envelope.canonical_hash)
            grant = self._approvals.get(key)
            if grant is not None:
                if time.monotonic() >= grant.expires_at:
                    del self._approvals[key]
                    return False
                # One-time use by default; pop on consumption.
                del self._approvals[key]
                return True

        # Check persistent SQLite pending approvals store
        pending = self._store.get_pending_approval(envelope.crossing_id)
        if (
            pending is not None
            and pending.status == "approved"
            and pending.canonical_hash == envelope.canonical_hash
            and pending.session_id == envelope.session_id
            and time.time() < pending.expires_at
        ):
            self._store.mark_approval_consumed(envelope.crossing_id)
            return True
        return False

    def grant_approval(self, *, canonical_hash: str, session_id: str | None = None) -> None:
        """Pre-approve a specific canonical_hash for one session until TTL expiry."""
        sid = session_id or self._session_id
        with self._lock:
            self._approvals[(sid, canonical_hash)] = ApprovalGrant(
                canonical_hash=canonical_hash,
                session_id=sid,
                expires_at=time.monotonic() + self._approval_ttl,
            )

    def consume_approval(self, canonical_hash: str, *, session_id: str | None = None) -> bool:
        """Explicitly consume/remove an in-memory approval grant."""
        sid = session_id or self._session_id
        with self._lock:
            return self._approvals.pop((sid, canonical_hash), None) is not None

    def get_session_taint(
        self,
        session_id: str | None = None,
        principal_id: str | None = None,
    ) -> str | None:
        """Return cumulative taint level from memory or durable SQLite."""
        sid = session_id or self._session_id
        if principal_id:
            pid = principal_id
        elif hasattr(self._store, "get_session"):
            sess = self._store.get_session(sid)
            if sess:
                pid = sess.principal_id
            elif session_id is None:
                pid = (
                    self._caller_context.authenticated_identity
                    if self._caller_context
                    else self._agent_id
                )
            else:
                pid = None
        elif session_id is None:
            pid = (
                self._caller_context.authenticated_identity
                if self._caller_context
                else self._agent_id
            )
        else:
            pid = None
        with self._lock:
            # 1. Check session taint
            s_taint = self._session_taints.get(sid)
            if s_taint is None:
                s_taint = self._store.get_session_taint(sid)
                if s_taint is not None:
                    self._session_taints[sid] = s_taint
            if s_taint == "untrusted":
                return "untrusted"

            # 2. Check principal taint (cannot be bypassed by creating a new session)
            if pid and hasattr(self._store, "get_principal_taint"):
                p_taint = self._store.get_principal_taint(pid)
                if p_taint == "untrusted":
                    return "untrusted"

            return s_taint

    def set_session_taint(
        self,
        taint: str,
        session_id: str | None = None,
        principal_id: str | None = None,
        caller_context: Any | None = None,
    ) -> None:
        """Explicitly set or clear session/principal taint in memory and durable SQLite."""
        sid = session_id or self._session_id
        if principal_id:
            pid = principal_id
        elif caller_context and getattr(caller_context, "authenticated_identity", None):
            pid = caller_context.authenticated_identity
        elif hasattr(self._store, "get_session"):
            sess = self._store.get_session(sid)
            if sess:
                pid = sess.principal_id
            elif session_id is None:
                pid = (
                    self._caller_context.authenticated_identity
                    if self._caller_context
                    else self._agent_id
                )
            else:
                pid = None
        elif session_id is None:
            pid = (
                self._caller_context.authenticated_identity
                if self._caller_context
                else self._agent_id
            )
        else:
            pid = None
        clean = taint.strip().lower()
        with self._lock:
            if clean in ("trusted", "clean", ""):
                ctx = caller_context or self._caller_context
                if ctx is not None and not (
                    ctx.is_trusted_operator
                    or ctx.has_scope("taint:clear")
                    or ctx.has_scope("operator:*")
                ):
                    from actentra_core.identity import IdentitySecurityError

                    raise IdentitySecurityError(
                        "Only authorized operators can clear or reset security taint"
                    )
                self._session_taints.pop(sid, None)
                self._store.set_session_taint(sid, "trusted")
                if pid and hasattr(self._store, "set_principal_taint"):
                    self._store.set_principal_taint(pid, "trusted")
            else:
                self._session_taints[sid] = clean
                self._store.set_session_taint(sid, clean)
                if pid and hasattr(self._store, "set_principal_taint"):
                    self._store.set_principal_taint(pid, clean)

    def dry_run(
        self,
        *,
        tool: str,
        verb: str,
        resource: str,
        params: dict[str, Any] | None = None,
        session_id: str | None = None,
        agent_id: str | None = None,
        user_goal: str | None = None,
        declared_by: Literal["human", "agent", "system"] = "agent",
        provenance: list[ProvenanceItem] | tuple[ProvenanceItem, ...] = (),
        warrant: Warrant | dict[str, Any] | None = None,
        record_receipt: bool = False,
    ) -> Decision:
        """Simulate action evaluation without executing it.

        Evaluates warrants, policy, risk tags, and session budgets. If record_receipt is True,
        records a shadow decision receipt into the receipt store for auditing.
        """
        effective_session = session_id or self._session_id
        effective_agent = agent_id or self._agent_id
        warrant_obj = self._check_warrant(
            warrant,
            tool=tool,
            resource=resource,
            effective_agent=effective_agent,
        )

        prov_items = list(provenance)
        if warrant_obj is not None:
            prov_items.append(
                ProvenanceItem(source=f"warrant:{warrant_obj.warrant_id}", trust="trusted")
            )
        if self.get_session_taint(effective_session) == "untrusted" and not any(
            p.trust == "untrusted" for p in prov_items
        ):
            prov_items.append(ProvenanceItem(source="session", trust="untrusted"))

        envelope = build_envelope(
            tool=tool,
            verb=verb,
            resource=resource,
            params=params,
            session_id=effective_session,
            agent_id=effective_agent,
            framework=self._framework,
            model=self._model,
            user_goal=user_goal,
            declared_by=declared_by,
            provenance=prov_items,
        )

        decision = self._engine.evaluate(envelope, record_rate_limit=False)

        if record_receipt:
            shadow_dec = Decision(
                verdict=decision.verdict,
                rule_id=f"{decision.rule_id}:dry-run",
                reason=f"[DRY-RUN] {decision.reason}",
                policy_version=decision.policy_version,
                canonical_hash=decision.canonical_hash,
                risk_tags=decision.risk_tags,
                constraints=decision.constraints,
                shadow=True,
                would_verdict=decision.verdict,
            )
            self._store.record_decision(envelope, shadow_dec)

        return decision

    def execute(
        self,
        *,
        tool: str,
        verb: str,
        resource: str,
        params: dict[str, Any] | None = None,
        fn: Callable[[ActionEnvelope, Decision], Any],
        user_goal: str | None = None,
        declared_by: Literal["human", "agent", "system"] = "agent",
        provenance: list[ProvenanceItem] | tuple[ProvenanceItem, ...] = (),
        warrant: Warrant | dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        verify_postcondition: bool = False,
        postcondition_claim: str = "exists",
        postcondition_expected_digest: str | None = None,
        raise_on_postcondition_failure: bool = False,
        caller_context: CallerContext | None = None,
    ) -> Any:
        """Evaluate an action, record a durable decision, enforce verdict, and record outcome."""
        ctx = caller_context or self._caller_context
        if ctx is not None and ctx.authenticated:
            if not ctx.is_agent_allowed(self._agent_id):
                deny_decision = Decision(
                    verdict=Verdict.DENY,
                    rule_id="identity:unauthorized-principal",
                    reason=(
                        f"Principal '{ctx.principal_id}' is not authorized to "
                        f"execute as agent '{self._agent_id}'"
                    ),
                    policy_version=self._engine.policy.policy_version,
                    canonical_hash="sha256:" + ("0" * 64),
                )
                raise ActionBlockedError(deny_decision, "UNAUTHORIZED_PRINCIPAL")
            if not ctx.has_scope("crossings:execute"):
                deny_decision = Decision(
                    verdict=Verdict.DENY,
                    rule_id="identity:scope-denied",
                    reason=f"Principal '{ctx.principal_id}' lacks scope 'crossings:execute'",
                    policy_version=self._engine.policy.policy_version,
                    canonical_hash="sha256:" + ("0" * 64),
                )
                raise ActionBlockedError(deny_decision, "SCOPE_DENIED")

        warrant_obj = self._check_warrant(
            warrant,
            tool=tool,
            resource=resource,
            effective_agent=self._agent_id,
        )
        if ctx is not None and warrant_obj is not None:
            clean_holder = warrant_obj.holder.strip().lower()
            auth_id = ctx.authenticated_identity.lower()
            del_id = ctx.delegated_by.lower() if ctx.delegated_by else None
            if clean_holder != auth_id and clean_holder != del_id and not ctx.is_trusted_operator:
                deny_decision = Decision(
                    verdict=Verdict.DENY,
                    rule_id="warrant:holder-mismatch",
                    reason=(
                        f"Warrant holder '{warrant_obj.holder}' mismatch with authenticated "
                        f"principal '{ctx.principal_id}'"
                    ),
                    policy_version=self._engine.policy.policy_version,
                    canonical_hash="sha256:" + ("0" * 64),
                )
                raise ActionBlockedError(deny_decision, "WARRANT_HOLDER_MISMATCH")

        prov_items = list(provenance)
        if ctx is not None:
            prov_items.append(
                ProvenanceItem(
                    source=f"principal:{ctx.authenticated_identity}",
                    trust="trusted" if ctx.is_trusted_operator else "untrusted",
                )
            )
        if warrant_obj is not None:
            prov_items.append(
                ProvenanceItem(source=f"warrant:{warrant_obj.warrant_id}", trust="trusted")
            )
        if self.get_session_taint(self._session_id) == "untrusted" and not any(
            p.trust == "untrusted" for p in prov_items
        ):
            prov_items.append(ProvenanceItem(source="session", trust="untrusted"))

        try:
            envelope = build_envelope(
                tool=tool,
                verb=verb,
                resource=resource,
                params=params,
                session_id=self._session_id,
                agent_id=self._agent_id,
                framework=self._framework,
                model=self._model,
                user_goal=user_goal,
                declared_by=declared_by,
                provenance=prov_items,
                idempotency_key=idempotency_key,
            )
        except EnvelopeError as exc:
            # Fail closed (I2): malformed/non-canonical action is never allowed.
            hold_decision = Decision(
                verdict=Verdict.HOLD,
                rule_id="kernel:envelope-invalid",
                reason=f"Action envelope failed canonicalization/validation: {exc}",
                policy_version=self._engine.policy.policy_version,
                canonical_hash="sha256:" + ("0" * 64),
            )
            raise ActionBlockedError(hold_decision, "INVALID") from exc

        # Multi-agent coordination conflict check:
        # mutating operations check for active lease conflicts
        if envelope.action.verb in ("write", "delete", "exec", "admin"):
            conflict = self._store.find_resource_conflict(
                resource=envelope.action.resource,
                agent_id=self._agent_id,
                mode="exclusive",
            )
            if conflict is not None:
                deny_decision = Decision(
                    verdict=Verdict.DENY,
                    rule_id="coordination:resource-locked",
                    reason=(
                        f"Resource '{envelope.action.resource}' is locked by agent "
                        f"'{conflict.owner_agent_id}' under lease '{conflict.lease_id}' "
                        f"until {conflict.expires_at}"
                    ),
                    policy_version=self._engine.policy.policy_version,
                    canonical_hash=envelope.canonical_hash,
                )
                self._store.record_decision(envelope, deny_decision)
                raise ActionBlockedError(deny_decision, envelope.crossing_id)

        # Update session and principal taint tracker if this action is untrusted
        if envelope.max_taint == "untrusted":
            self.set_session_taint(
                "untrusted",
                session_id=envelope.session_id,
                principal_id=envelope.agent.id,
            )

        decision = self._engine.evaluate(envelope)

        # Handle ASK escalation bound to (session_id, canonical_hash) (I4).
        if decision.verdict == Verdict.ASK:
            approved = self._has_valid_approval(envelope)
            if not approved and self._approval_callback is not None:
                try:
                    approved = bool(self._approval_callback(envelope, decision))
                except Exception:
                    approved = False
            if approved:
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

        # I5: No action may execute unless its decision record is durable.
        try:
            self._store.record_decision(envelope, decision)
        except ReceiptError as exc:
            hold_decision = Decision(
                verdict=Verdict.HOLD,
                rule_id="kernel:receipt-unavailable",
                reason="Unable to persist decision receipt; failing closed",
                policy_version=decision.policy_version,
                canonical_hash=envelope.canonical_hash,
                risk_tags=decision.risk_tags,
            )
            raise ActionBlockedError(hold_decision, envelope.crossing_id) from exc

        if not decision.verdict.permits_execution:
            raise ActionBlockedError(decision, envelope.crossing_id)

        # Record warrant consumption if registry is configured
        if self._warrant_registry is not None and warrant_obj is not None:
            try:
                self._warrant_registry.record_use(warrant_obj)
            except WarrantError as exc:
                exhausted_decision = Decision(
                    verdict=Verdict.DENY,
                    rule_id="warrant:exhausted",
                    reason=str(exc),
                    policy_version=decision.policy_version,
                    canonical_hash=envelope.canonical_hash,
                )
                self._store.record_outcome(
                    crossing_id=envelope.crossing_id,
                    session_id=envelope.session_id,
                    canonical_hash=envelope.canonical_hash,
                    policy_version=decision.policy_version,
                    status="failure",
                    error=str(exc),
                    evidence_status="locally_observed",
                )
                raise ActionBlockedError(exhausted_decision, envelope.crossing_id) from exc

        # I3: Verify evaluated hash matches action payload immediately before execution.
        verify_hash = compute_action_hash(
            envelope_version=envelope.envelope_version,
            session_id=envelope.session_id,
            agent_id=envelope.agent.id,
            action=envelope.action,
        )
        if verify_hash != decision.canonical_hash:
            self._store.record_outcome(
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
            result = fn(envelope, decision)
        except Exception as exc:
            err_label = type(exc).__name__
            if self._secrets_broker is not None:
                err_label = self._secrets_broker.redact(err_label)
            self._store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="failure",
                error=err_label,
                evidence_status="locally_observed",
            )
            raise

        result_hash: str | None = None
        try:
            if result is not None:
                result_hash = hash_canonical(result)
        except (TypeError, ValueError, CanonicalizationError):
            result_hash = None

        if not verify_postcondition:
            self._store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="success",
                result_hash=result_hash,
                evidence_status="locally_observed",
            )
            self._engine.budget_tracker.record_usage(envelope)
            return result

        # Postcondition verification requested: finalize outcome strictly after verification
        if self._verifier is None:
            self._store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="unknown",
                result_hash=result_hash,
                error=(
                    "Postcondition verification requested but no verifier is configured on Boundary"
                ),
                reason="postcondition_unverified",
                evidence_status="unknown",
            )
            if raise_on_postcondition_failure:
                raise PostconditionFailedError(
                    None,
                    "unknown",
                    "Postcondition verification requested but no verifier is "
                    "configured on Boundary",
                )
            return result

        obs: ObservationRecord | None = None
        try:
            kwargs: dict[str, Any] = {"crossing_id": envelope.crossing_id}
            if postcondition_expected_digest is not None:
                kwargs["expected_digest"] = postcondition_expected_digest
            try:
                obs = self._verifier.verify(
                    resource=envelope.action.resource,
                    claim=postcondition_claim,
                    **kwargs,
                )
            except TypeError:
                obs = self._verifier.verify(
                    resource=envelope.action.resource,
                    claim=postcondition_claim,
                )
        except Exception as exc:
            obs = build_observation(
                subject_resource=envelope.action.resource,
                claim=postcondition_claim,
                status="error",
                verifier_id=getattr(self._verifier, "verifier_id", "actentra.verifier.unknown"),
                verifier_version=getattr(self._verifier, "verifier_version", "1.0.0"),
                trust_domain="local_host",
                crossing_id=envelope.crossing_id,
                error=f"Verifier raised exception: {exc}",
            )

        if obs.status == "verified":
            self._store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="success",
                result_hash=result_hash,
                evidence_status="externally_verified",
                observation=obs,
            )
            # Update session and principal cumulative budgets only on verified success
            self._engine.budget_tracker.record_usage(
                envelope,
                principal_id=envelope.agent.id,
            )

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
            self._store.record_evidence(ev)
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
            self._store.record_causal_link(link)
            return result

        elif obs.status == "refuted":
            err_msg = (
                f"Postcondition refuted: claim '{postcondition_claim}' on resource "
                f"'{envelope.action.resource}'"
            )
            if obs.error:
                err_msg += f" ({obs.error})"
            self._store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="failure",
                result_hash=result_hash,
                error=err_msg,
                reason="postcondition_refuted",
                evidence_status="locally_observed",
                observation=obs,
            )
            if raise_on_postcondition_failure:
                raise PostconditionFailedError(obs, "failure", err_msg)
            return result

        else:
            status_label = obs.status
            err_msg = (
                f"Postcondition verification status is '{status_label}' for claim "
                f"'{postcondition_claim}'"
            )
            if obs.error:
                err_msg += f": {obs.error}"
            ev_status = "stale" if status_label == "stale" else "unknown"
            self._store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="unknown",
                result_hash=result_hash,
                error=err_msg,
                reason=f"postcondition_{status_label}",
                evidence_status=ev_status,
                observation=obs,
            )
            if raise_on_postcondition_failure:
                raise PostconditionFailedError(obs, "unknown", err_msg)
            return result

    def acquire_lease(
        self,
        resource: str,
        *,
        mode: LeaseMode = "exclusive",
        ttl_seconds: float = 60.0,
        metadata: dict[str, Any] | None = None,
    ) -> ResourceLease:
        """Acquire a durable resource lease for this agent and session."""
        lease = build_lease(
            resource=resource,
            owner_agent_id=self._agent_id,
            session_id=self._session_id,
            mode=mode,
            ttl_seconds=ttl_seconds,
            metadata=metadata,
        )
        return self._store.acquire_lease(lease)

    def release_lease(self, lease_id: str) -> bool:
        """Release a resource lease owned by this agent."""
        return self._store.release_lease(lease_id, owner_agent_id=self._agent_id)

    def list_active_leases(self) -> list[ResourceLease]:
        """List currently active resource leases."""
        return self._store.list_leases(status="active")

    def verify_state(
        self,
        resource: str,
        claim: str = "exists",
        *,
        crossing_id: str | None = None,
        expected_digest: str | None = None,
        ttl_seconds: float = 60.0,
    ) -> ObservationRecord:
        """Execute verifiable state check through the configured verifier."""
        if self._verifier is None:
            raise ValueError("No verifier configured on Boundary")
        obs = self._verifier.verify(
            resource=resource,
            claim=claim,
            crossing_id=crossing_id,
            expected_digest=expected_digest,
            ttl_seconds=ttl_seconds,
        )
        self._store.record_observation(obs)
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
                self._store.record_evidence(ev)
        return cast(ObservationRecord, obs)

    def guard(
        self,
        *,
        tool: str,
        verb: str,
        resource_fn: Callable[..., str],
    ) -> Callable[[F], F]:
        """Decorator protecting a Python tool function behind this Boundary."""

        def decorator(func: F) -> F:
            sig = inspect.signature(func)

            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                resource = resource_fn(*args, **kwargs)
                params = dict(bound.arguments)
                return self.execute(
                    tool=tool,
                    verb=verb,
                    resource=resource,
                    params=params,
                    fn=lambda _env, _dec: func(*args, **kwargs),
                )

            return wrapper  # type: ignore[return-value]

        return decorator
