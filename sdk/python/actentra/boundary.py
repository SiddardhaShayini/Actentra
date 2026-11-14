"""In-process Python SDK for Actentra execution boundaries."""

from __future__ import annotations

import functools
import inspect
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, TypeVar

from actentra.secrets import SecretsBroker
from actentra_core.canonicalize import CanonicalizationError, hash_canonical
from actentra_core.envelope import (
    ActionEnvelope,
    EnvelopeError,
    ProvenanceItem,
    build_envelope,
    compute_action_hash,
)
from actentra_core.policy import PolicyEngine, PolicyPack, load_policy_file
from actentra_core.receipts import ReceiptError, ReceiptStore
from actentra_core.verdict import Decision, Verdict

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
    ) -> None:
        self._engine = PolicyEngine(policy)
        self._store = receipt_store
        self._session_id = session_id
        self._agent_id = agent_id
        self._framework = framework
        self._model = model
        self._approval_callback = approval_callback
        self._approval_ttl = approval_ttl_seconds
        self._secrets_broker = secrets_broker
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
    ) -> Boundary:
        policy = load_policy_file(policy_path)
        store = ReceiptStore(receipts_db)
        return cls(
            policy=policy,
            receipt_store=store,
            session_id=session_id,
            agent_id=agent_id,
            approval_callback=approval_callback,
        )

    @property
    def engine(self) -> PolicyEngine:
        return self._engine

    @property
    def receipt_store(self) -> ReceiptStore:
        return self._store

    @property
    def secrets_broker(self) -> SecretsBroker | None:
        return self._secrets_broker

    def freeze(self) -> None:
        self._engine.freeze()

    def unfreeze(self) -> None:
        self._engine.unfreeze()

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

    def get_session_taint(self, session_id: str | None = None) -> str | None:
        """Return the cumulative taint level for a session."""
        sid = session_id or self._session_id
        with self._lock:
            return self._session_taints.get(sid)

    def set_session_taint(self, taint: str, session_id: str | None = None) -> None:
        """Explicitly set or clear session-level taint."""
        sid = session_id or self._session_id
        clean = taint.strip().lower()
        with self._lock:
            if clean in ("trusted", "clean", ""):
                self._session_taints.pop(sid, None)
            else:
                self._session_taints[sid] = clean

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
        record_receipt: bool = False,
    ) -> Decision:
        """Simulate action evaluation without executing it.

        Evaluates policy, risk tags, and session budgets. If record_receipt is True,
        records a shadow decision receipt into the receipt store for auditing.
        """
        effective_session = session_id or self._session_id
        effective_agent = agent_id or self._agent_id
        prov_items = list(provenance)
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
        idempotency_key: str | None = None,
    ) -> Any:
        """Evaluate an action, record a durable decision, enforce verdict, and record outcome."""
        prov_items = list(provenance)
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

        # Update session taint tracker if this action is untrusted
        if envelope.max_taint == "untrusted":
            self._session_taints[envelope.session_id] = "untrusted"

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
            )
            raise

        result_hash: str | None = None
        try:
            if result is not None:
                result_hash = hash_canonical(result)
        except (TypeError, ValueError, CanonicalizationError):
            result_hash = None

        self._store.record_outcome(
            crossing_id=envelope.crossing_id,
            session_id=envelope.session_id,
            canonical_hash=envelope.canonical_hash,
            policy_version=decision.policy_version,
            status="success",
            result_hash=result_hash,
        )
        # Update session cumulative budgets
        self._engine.budget_tracker.record_usage(envelope)
        return result

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
