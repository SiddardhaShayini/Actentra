"""In-process Python SDK for Actentra execution boundaries."""

from __future__ import annotations

import contextlib
import functools
import inspect
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypeVar, cast

from actentra.secrets import SecretsBroker
from actentra_core.canonicalize import (
    CanonicalizationError,
    canonicalize_windows_path,
    hash_canonical,
)
from actentra_core.causal import CausalLink, generate_link_id
from actentra_core.context import (
    ContextError,
    PostconditionSpec,
    build_execution_context,
    compute_content_digest,
    validate_postcondition_semantics,
)
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
from actentra_core.observability import get_global_metrics
from actentra_core.observations import ObservationRecord, build_observation
from actentra_core.policy import PolicyEngine, PolicyPack, load_policy_file, load_policy_yaml
from actentra_core.receipts import (
    ReceiptError,
    ReceiptRecord,
    ReceiptStore,
    VerificationResult,
    verify_log,
)
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


@dataclass(frozen=True, slots=True)
class CrossingReceipt:
    """Consolidated view of a crossing's decision, outcome, observation, and lifecycle."""

    crossing_id: str
    decision: ReceiptRecord | None
    outcome: ReceiptRecord | None
    observation: ObservationRecord | None
    envelope: dict[str, Any] | None
    lifecycle_state: str | None
    verified: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "crossing_id": self.crossing_id,
            "decision": self.decision.to_dict() if self.decision is not None else None,
            "outcome": self.outcome.to_dict() if self.outcome is not None else None,
            "observation": self.observation.to_dict() if self.observation is not None else None,
            "envelope": dict(self.envelope) if self.envelope is not None else None,
            "lifecycle_state": self.lifecycle_state,
            "verified": self.verified,
        }


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Structured result returned by ``Boundary.run()`` with decision, outcome, and receipt."""

    crossing_id: str
    allowed: bool
    verdict: Verdict
    rule_id: str
    reason: str
    status: str
    evidence_status: str | None
    verified: bool
    result: Any
    result_hash: str | None
    canonical_hash: str
    decision_receipt: ReceiptRecord | None = None
    outcome_receipt: ReceiptRecord | None = None
    observation: ObservationRecord | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "crossing_id": self.crossing_id,
            "allowed": self.allowed,
            "verdict": self.verdict.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "status": self.status,
            "evidence_status": self.evidence_status,
            "verified": self.verified,
            "result": self.result,
            "result_hash": self.result_hash,
            "canonical_hash": self.canonical_hash,
            "decision_receipt": (
                self.decision_receipt.to_dict() if self.decision_receipt is not None else None
            ),
            "outcome_receipt": (
                self.outcome_receipt.to_dict() if self.outcome_receipt is not None else None
            ),
            "observation": self.observation.to_dict() if self.observation is not None else None,
        }


def path_resource(path: str | Path, *, workspace_root: str | Path | None = None) -> str:
    """Build a canonical ``path:...`` resource identifier safely without hiding traversal.

    When ``workspace_root`` is provided, relative paths are anchored to ``workspace_root``
    and any ``..`` escape raises ``CanonicalizationError``.
    """
    raw = str(path)
    if raw.lower().startswith("path:"):
        raw = raw[5:]
    base: str | None = None
    if workspace_root is not None:
        base = canonicalize_windows_path(str(Path(workspace_root).resolve()), resolve_fs=True)
    else:
        win_slash = raw.replace("/", "\\")
        has_drive = (
            len(win_slash) >= 2
            and win_slash[0].isascii()
            and win_slash[0].isalpha()
            and win_slash[1] == ":"
        )
        if not has_drive and not win_slash.startswith("\\\\") and (
            os.name == "nt" or not raw.startswith("/")
        ):
            base = canonicalize_windows_path(str(Path.cwd()), resolve_fs=True)
    canon = canonicalize_windows_path(raw, base_dir=base, resolve_fs=True)
    return f"path:{canon}"


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
        self._executors: dict[str, Callable[[ActionEnvelope, Decision], Any]] = {}
        self._lock = threading.Lock()
        self._approvals: dict[tuple[str, str], ApprovalGrant] = {}
        self._session_taints: dict[str, str] = {}
        # Phase 7: Automatically recover and reconcile system state on startup
        self._store.recover_system_state()

    @classmethod
    def from_files(
        cls,
        *,
        policy_path: str | Path,
        receipts_db: str | Path,
        workspace_root: str | Path | None = None,
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
    ) -> Boundary:
        """Create a Boundary from a YAML policy file and SQLite receipt database path."""
        policy_file = Path(policy_path)
        if not policy_file.exists():
            raise FileNotFoundError(
                f"Policy file not found: {policy_file}. "
                "Generate one with `actentra init --workspace .` or use `Boundary.from_yaml(...)`."
            )
        policy = load_policy_file(policy_file)
        store = ReceiptStore(receipts_db)
        boundary = cls(
            policy=policy,
            receipt_store=store,
            session_id=session_id,
            agent_id=agent_id,
            framework=framework,
            model=model,
            approval_callback=approval_callback,
            approval_ttl_seconds=approval_ttl_seconds,
            secrets_broker=secrets_broker,
            warrant_public_key=warrant_public_key,
            warrant_registry=warrant_registry,
            verifier=verifier,
            caller_context=caller_context,
        )
        if workspace_root is not None:
            boundary.register_fs(workspace_root, configure_verifier=(verifier is None))
        return boundary

    @classmethod
    def from_yaml(
        cls,
        *,
        policy_yaml: str,
        receipts_db: str | Path,
        workspace_root: str | Path | None = None,
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
    ) -> Boundary:
        """Create a Boundary directly from an inline YAML policy string and SQLite DB path."""
        policy = load_policy_yaml(policy_yaml)
        store = ReceiptStore(receipts_db)
        boundary = cls(
            policy=policy,
            receipt_store=store,
            session_id=session_id,
            agent_id=agent_id,
            framework=framework,
            model=model,
            approval_callback=approval_callback,
            approval_ttl_seconds=approval_ttl_seconds,
            secrets_broker=secrets_broker,
            warrant_public_key=warrant_public_key,
            warrant_registry=warrant_registry,
            verifier=verifier,
            caller_context=caller_context,
        )
        if workspace_root is not None:
            boundary.register_fs(workspace_root, configure_verifier=(verifier is None))
        return boundary

    def register_executor(
        self,
        tool_name: str,
        fn: Callable[[ActionEnvelope, Decision], Any],
    ) -> None:
        """Register an executor callable for a tool name used by ``Boundary.run()``."""
        clean = tool_name.strip().lower()
        if not clean:
            raise ValueError("tool_name must be non-empty")
        with self._lock:
            self._executors[clean] = fn

    def register_fs(
        self,
        workspace_root: str | Path,
        *,
        configure_verifier: bool = True,
    ) -> Any:
        """Register ``LocalFSExecutor`` for ``fs.*`` tools and optionally set file verifier."""
        from actentra_executors.fs import LocalFSExecutor
        from actentra_executors.verifiers import WorkspaceFileVerifier

        executor = LocalFSExecutor(workspace_root)
        for tool_name in ("fs.list", "fs.read", "fs.write", "fs.delete"):
            self.register_executor(tool_name, executor.execute)
        if configure_verifier and self._verifier is None:
            self._verifier = WorkspaceFileVerifier(workspace_root)
        return executor

    def register_sqlite(self, db_path: str | Path) -> Any:
        """Register ``ScopedSQLiteExecutor`` for ``sql.execute``."""
        from actentra_executors.sqlite import ScopedSQLiteExecutor

        executor = ScopedSQLiteExecutor(db_path)
        self.register_executor("sql.execute", executor.execute)
        return executor

    def register_http(self, allowed_hosts: list[str] | None = None) -> Any:
        """Register ``ScopedHTTPExecutor`` for ``http.*`` tools."""
        from actentra_executors.http import ScopedHTTPExecutor

        executor = ScopedHTTPExecutor(allowed_hosts=allowed_hosts)
        for tool_name in ("http.get", "http.post", "http.request"):
            self.register_executor(tool_name, executor.execute)
        return executor

    @property
    def registered_tools(self) -> list[str]:
        """List tool names currently registered on this Boundary."""
        with self._lock:
            return sorted(self._executors.keys())

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
        postcondition_claim: str | None = None,
        postcondition_expected_digest: str | None = None,
        raise_on_postcondition_failure: bool = False,
        strict_postconditions: bool = False,
        caller_context: CallerContext | None = None,
    ) -> Any:
        """Evaluate an action, record a durable decision, enforce verdict, and record outcome."""
        result, _crossing_id = self._execute_internal(
            tool=tool,
            verb=verb,
            resource=resource,
            params=params,
            fn=fn,
            user_goal=user_goal,
            declared_by=declared_by,
            provenance=provenance,
            warrant=warrant,
            idempotency_key=idempotency_key,
            verify_postcondition=verify_postcondition,
            postcondition_claim=postcondition_claim,
            postcondition_expected_digest=postcondition_expected_digest,
            raise_on_postcondition_failure=raise_on_postcondition_failure,
            strict_postconditions=strict_postconditions,
            caller_context=caller_context,
        )
        return result

    def _execute_internal(
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
        postcondition_claim: str | None = None,
        postcondition_expected_digest: str | None = None,
        raise_on_postcondition_failure: bool = False,
        strict_postconditions: bool = False,
        caller_context: CallerContext | None = None,
        auto_default_postcondition: bool = False,
    ) -> tuple[Any, str]:
        """Internal execution helper returning ``(result, crossing_id)``."""
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

        # Phase 7 (Invariant I16): Durable Idempotency Check & Registration
        effective_principal_id = ctx.authenticated_identity if ctx else envelope.agent.id
        if idempotency_key:
            cached_idemp = self._store.register_idempotency_key(
                idempotency_key=idempotency_key,
                principal_id=effective_principal_id,
                canonical_hash=envelope.canonical_hash,
                tool=envelope.action.tool,
                verb=envelope.action.verb,
                crossing_id=envelope.crossing_id,
            )
            if cached_idemp is not None:
                if cached_idemp.status == "completed":
                    if cached_idemp.response and "result" in cached_idemp.response:
                        return cached_idemp.response["result"], cached_idemp.crossing_id
                    return None, cached_idemp.crossing_id
                elif cached_idemp.status == "failed":
                    err_msg = (
                        cached_idemp.response.get("error", "Action previously failed")
                        if cached_idemp.response
                        else "Action previously failed"
                    )
                    raise ActentraError(
                        f"Cached failure for idempotency key '{idempotency_key}': {err_msg}"
                    )

        # Phase 7: Initialize action lifecycle state machine (CREATED)
        self._store.create_action_lifecycle(
            crossing_id=envelope.crossing_id,
            session_id=envelope.session_id,
            principal_id=effective_principal_id,
            canonical_hash=envelope.canonical_hash,
            idempotency_key=idempotency_key,
            initial_state="created",
        )

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
                self._store.transition_action_state(
                    envelope.crossing_id,
                    "failed",
                    actor_id="policy",
                    reason="coordination:resource-locked",
                )
                if idempotency_key:
                    self._store.finalize_idempotency_key(
                        idempotency_key=idempotency_key,
                        principal_id=effective_principal_id,
                        crossing_id=envelope.crossing_id,
                        status="failed",
                        response={"error": "coordination:resource-locked"},
                    )
                raise ActionBlockedError(deny_decision, envelope.crossing_id)

        # Update session and principal taint tracker if this action is untrusted
        if envelope.max_taint == "untrusted":
            self.set_session_taint(
                "untrusted",
                session_id=envelope.session_id,
                principal_id=envelope.agent.id,
            )

        decision = self._engine.evaluate(envelope)
        get_global_metrics().increment("crossings_total")
        if decision.verdict == Verdict.ALLOW:
            get_global_metrics().increment("crossings_allowed")
        elif decision.verdict == Verdict.DENY:
            get_global_metrics().increment("crossings_denied")
        elif decision.verdict == Verdict.ASK:
            get_global_metrics().increment("crossings_asked")
        elif decision.verdict == Verdict.HOLD:
            get_global_metrics().increment("crossings_held")

        # Handle ASK escalation bound to (session_id, canonical_hash) (I4).
        if decision.verdict == Verdict.ASK:
            approved = self._has_valid_approval(envelope)
            if not approved and self._approval_callback is not None:
                try:
                    approved = bool(self._approval_callback(envelope, decision))
                except Exception:
                    approved = False
            if approved:
                self._store.transition_action_state(
                    envelope.crossing_id,
                    "authorized",
                    actor_id="policy",
                    reason=decision.reason,
                )
                self._store.transition_action_state(
                    envelope.crossing_id,
                    "approved",
                    actor_id="human",
                    reason="human_approved",
                )
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
            else:
                self._store.record_decision(envelope, decision)
                self._store.transition_action_state(
                    envelope.crossing_id,
                    "failed",
                    actor_id="policy",
                    reason="ask_unapproved",
                )
                if idempotency_key:
                    self._store.finalize_idempotency_key(
                        idempotency_key=idempotency_key,
                        principal_id=effective_principal_id,
                        crossing_id=envelope.crossing_id,
                        status="failed",
                        response={"error": "ask_unapproved"},
                    )
                raise ActionBlockedError(decision, envelope.crossing_id)

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
            self._store.transition_action_state(
                envelope.crossing_id,
                "failed",
                actor_id="kernel",
                reason="receipt_unavailable",
            )
            if idempotency_key:
                self._store.finalize_idempotency_key(
                    idempotency_key=idempotency_key,
                    principal_id=effective_principal_id,
                    crossing_id=envelope.crossing_id,
                    status="failed",
                    response={"error": "receipt_unavailable"},
                )
            raise ActionBlockedError(hold_decision, envelope.crossing_id) from exc

        if not decision.verdict.permits_execution:
            self._store.transition_action_state(
                envelope.crossing_id,
                "failed",
                actor_id="policy",
                reason=decision.reason,
            )
            if idempotency_key:
                self._store.finalize_idempotency_key(
                    idempotency_key=idempotency_key,
                    principal_id=effective_principal_id,
                    crossing_id=envelope.crossing_id,
                    status="failed",
                    response={"error": decision.reason},
                )
            raise ActionBlockedError(decision, envelope.crossing_id)

        # Transition to authorized (if not already transitioned via approval)
        cur_lf = self._store.get_action_lifecycle(envelope.crossing_id)
        if cur_lf and cur_lf.current_state == "created":
            self._store.transition_action_state(
                envelope.crossing_id,
                "authorized",
                actor_id="policy",
                reason=decision.reason,
            )

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

        # Phase 5 (ACT-06): Policy-mandated postconditions and execution integrity binding
        policy_require_post = bool(
            decision.constraints.get("require_postcondition")
            or "postcondition" in decision.constraints
            or "required_postconditions" in decision.constraints
            or decision.constraints.get("strict_postconditions")
        )
        effective_verify_postcondition = verify_postcondition or policy_require_post
        is_strict = strict_postconditions or policy_require_post

        policy_post_claim = decision.constraints.get("postcondition")
        policy_expected_digest = decision.constraints.get("expected_digest")

        effective_expected_digest = postcondition_expected_digest

        if policy_post_claim:
            if postcondition_claim is not None and postcondition_claim != policy_post_claim:
                err_msg = (
                    f"Postcondition claim substitution rejected: policy requires "
                    f"'{policy_post_claim}', caller requested '{postcondition_claim}'"
                )
                self._store.record_outcome(
                    crossing_id=envelope.crossing_id,
                    session_id=envelope.session_id,
                    canonical_hash=envelope.canonical_hash,
                    policy_version=decision.policy_version,
                    status="failure",
                    error=err_msg,
                    reason="postcondition_substitution_rejected",
                    evidence_status="locally_observed",
                )
                raise PostconditionFailedError(None, "failure", err_msg)
            effective_claim = str(policy_post_claim)
        elif postcondition_claim is not None:
            effective_claim = postcondition_claim
        elif auto_default_postcondition and effective_verify_postcondition:
            norm_tool = envelope.action.tool.strip().lower()
            norm_verb = envelope.action.verb.strip().lower()
            if (norm_verb == "write" or norm_tool == "fs.write") and isinstance(
                envelope.action.params.get("content"), (str, bytes)
            ):
                effective_claim = "digest_match"
            elif norm_verb == "delete" or norm_tool == "fs.delete":
                effective_claim = "absent"
            else:
                effective_claim = "exists"
        else:
            effective_claim = "exists"

        if policy_expected_digest:
            if (
                postcondition_expected_digest
                and postcondition_expected_digest.lower() != str(policy_expected_digest).lower()
            ):
                err_msg = (
                    f"Postcondition expected digest substitution rejected: policy requires "
                    f"'{policy_expected_digest}', caller requested "
                    f"'{postcondition_expected_digest}'"
                )
                self._store.record_outcome(
                    crossing_id=envelope.crossing_id,
                    session_id=envelope.session_id,
                    canonical_hash=envelope.canonical_hash,
                    policy_version=decision.policy_version,
                    status="failure",
                    error=err_msg,
                    reason="postcondition_substitution_rejected",
                    evidence_status="locally_observed",
                )
                raise PostconditionFailedError(None, "failure", err_msg)
            effective_expected_digest = str(policy_expected_digest)

        validated_postcondition: PostconditionSpec | None = None
        if effective_verify_postcondition or postcondition_claim != "exists" or is_strict:
            try:
                validated_postcondition = validate_postcondition_semantics(
                    tool=envelope.action.tool,
                    verb=envelope.action.verb,
                    resource=envelope.action.resource,
                    claim=effective_claim,
                    params=envelope.action.params,
                    expected_digest=effective_expected_digest,
                    strict=is_strict,
                )
                effective_claim = validated_postcondition.claim
                effective_expected_digest = validated_postcondition.expected_digest
            except ContextError as exc:
                err_msg = f"Invalid postcondition semantics: {exc}"
                self._store.record_outcome(
                    crossing_id=envelope.crossing_id,
                    session_id=envelope.session_id,
                    canonical_hash=envelope.canonical_hash,
                    policy_version=decision.policy_version,
                    status="failure",
                    error=err_msg,
                    reason="invalid_postcondition_semantics",
                    evidence_status="locally_observed",
                )
                raise PostconditionFailedError(None, "failure", err_msg) from exc

        # Bind into AuthorizedExecutionContext (Phase 5: Invariant I14)
        principal_id = ctx.authenticated_identity if ctx else envelope.agent.id
        executor_id = getattr(self._verifier, "verifier_id", "in-process-executor")
        approval_id = (
            f"approval:{envelope.crossing_id}" if decision.rule_id.endswith(":approved") else None
        )
        post_specs = [validated_postcondition] if validated_postcondition else []

        exec_ctx = build_execution_context(
            crossing_id=envelope.crossing_id,
            tool=envelope.action.tool,
            verb=envelope.action.verb,
            resource=envelope.action.resource,
            params=envelope.action.params,
            principal_id=principal_id,
            executor_id=executor_id,
            approval_id=approval_id,
            policy_version=decision.policy_version,
            required_postconditions=post_specs,
            expected_result_constraints=decision.constraints.get("expected_result", {}),
        )

        appr_or_war = approval_id or (f"warrant:{warrant_obj.warrant_id}" if warrant_obj else None)
        claim = self._store.issue_execution_claim(
            crossing_id=envelope.crossing_id,
            executor_principal_id=principal_id,
            session_id=envelope.session_id,
            canonical_hash=envelope.canonical_hash,
            approval_or_warrant_id=appr_or_war,
            context_hash=exec_ctx.context_hash,
        )
        self._store.transition_action_state(
            envelope.crossing_id,
            "claimed",
            actor_id=principal_id,
            reason="execution_claim_issued",
        )

        self._store.transition_action_state(
            envelope.crossing_id,
            "executing",
            actor_id=principal_id,
            reason="dispatching_execution",
        )
        get_global_metrics().increment("executions_dispatched")
        t0 = time.time()

        try:
            result = fn(envelope, decision)
        except Exception as exc:
            err_label = type(exc).__name__
            if self._secrets_broker is not None:
                err_label = self._secrets_broker.redact(err_label)
            with contextlib.suppress(Exception):
                self._store.consume_execution_claim(
                    claim.claim_id,
                    executor_principal_id=principal_id,
                    crossing_id=envelope.crossing_id,
                    canonical_hash=envelope.canonical_hash,
                    approval_or_warrant_id=claim.approval_or_warrant_id,
                    verification_status="error",
                )
            self._store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="failure",
                error=err_label,
                evidence_status="locally_observed",
            )
            self._store.transition_action_state(
                envelope.crossing_id,
                "failed",
                actor_id=principal_id,
                reason=err_label,
            )
            if idempotency_key:
                self._store.finalize_idempotency_key(
                    idempotency_key=idempotency_key,
                    principal_id=effective_principal_id,
                    crossing_id=envelope.crossing_id,
                    status="failed",
                    response={"error": err_label},
                )
            get_global_metrics().increment("executions_failed")
            raise

        result_hash: str | None = None
        try:
            if result is not None:
                result_hash = hash_canonical(result)
        except (TypeError, ValueError, CanonicalizationError):
            result_hash = None

        if not effective_verify_postcondition:
            with contextlib.suppress(Exception):
                self._store.consume_execution_claim(
                    claim.claim_id,
                    executor_principal_id=principal_id,
                    crossing_id=envelope.crossing_id,
                    canonical_hash=envelope.canonical_hash,
                    approval_or_warrant_id=claim.approval_or_warrant_id,
                    result_digest=result_hash,
                    verification_status="unverified",
                )
            self._store.record_outcome(
                crossing_id=envelope.crossing_id,
                session_id=envelope.session_id,
                canonical_hash=envelope.canonical_hash,
                policy_version=decision.policy_version,
                status="success",
                result_hash=result_hash,
                evidence_status="locally_observed",
            )
            self._store.transition_action_state(
                envelope.crossing_id,
                "succeeded",
                actor_id=principal_id,
                reason="execution_completed",
            )
            if idempotency_key:
                self._store.finalize_idempotency_key(
                    idempotency_key=idempotency_key,
                    principal_id=effective_principal_id,
                    crossing_id=envelope.crossing_id,
                    status="completed",
                    result_hash=result_hash,
                    response={"result": result, "status": "success"},
                )
            get_global_metrics().increment("executions_succeeded")
            get_global_metrics().record_latency(f"tool:{envelope.action.tool}", time.time() - t0)
            self._engine.budget_tracker.record_usage(envelope)
            return result, envelope.crossing_id

        # Postcondition verification requested: finalize outcome strictly after verification
        self._store.transition_action_state(
            envelope.crossing_id,
            "verification_pending",
            actor_id=principal_id,
            reason="verifying_postcondition",
        )
        if self._verifier is None:
            with contextlib.suppress(Exception):
                self._store.consume_execution_claim(
                    claim.claim_id,
                    executor_principal_id=principal_id,
                    crossing_id=envelope.crossing_id,
                    canonical_hash=envelope.canonical_hash,
                    approval_or_warrant_id=claim.approval_or_warrant_id,
                    result_digest=result_hash,
                    verification_status="unknown",
                )
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
            self._store.transition_action_state(
                envelope.crossing_id,
                "unknown",
                actor_id=principal_id,
                reason="postcondition_unverified",
            )
            if idempotency_key:
                self._store.finalize_idempotency_key(
                    idempotency_key=idempotency_key,
                    principal_id=effective_principal_id,
                    crossing_id=envelope.crossing_id,
                    status="reconciliation_required",
                    result_hash=result_hash,
                    response={"status": "unknown"},
                )
            get_global_metrics().increment("executions_unknown")
            if raise_on_postcondition_failure:
                raise PostconditionFailedError(
                    None,
                    "unknown",
                    "Postcondition verification requested but no verifier is "
                    "configured on Boundary",
                )
            return result, envelope.crossing_id

        obs: ObservationRecord | None = None
        target_claim = validated_postcondition.claim if validated_postcondition else effective_claim
        target_res = (
            validated_postcondition.resource
            if validated_postcondition
            else envelope.action.resource
        )
        target_digest = (
            validated_postcondition.expected_digest
            if validated_postcondition
            else effective_expected_digest
        )

        try:
            kwargs: dict[str, Any] = {"crossing_id": envelope.crossing_id}
            if target_digest is not None:
                kwargs["expected_digest"] = target_digest
            try:
                obs = self._verifier.verify(
                    resource=target_res,
                    claim=target_claim,
                    **kwargs,
                )
            except TypeError:
                obs = self._verifier.verify(
                    resource=target_res,
                    claim=target_claim,
                )
        except Exception as exc:
            obs = build_observation(
                subject_resource=target_res,
                claim=target_claim,
                status="error",
                verifier_id=getattr(self._verifier, "verifier_id", "actentra.verifier.unknown"),
                verifier_version=getattr(self._verifier, "verifier_version", "1.0.0"),
                trust_domain="local_host",
                crossing_id=envelope.crossing_id,
                error=f"Verifier raised exception: {exc}",
            )

        if obs.status == "verified":
            with contextlib.suppress(Exception):
                self._store.consume_execution_claim(
                    claim.claim_id,
                    executor_principal_id=principal_id,
                    crossing_id=envelope.crossing_id,
                    canonical_hash=envelope.canonical_hash,
                    approval_or_warrant_id=claim.approval_or_warrant_id,
                    result_digest=result_hash,
                    evidence_id=obs.observation_id,
                    verification_status="verified",
                )
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
            self._store.transition_action_state(
                envelope.crossing_id,
                "succeeded",
                actor_id=obs.verifier_id,
                reason="postcondition_verified",
            )
            if idempotency_key:
                self._store.finalize_idempotency_key(
                    idempotency_key=idempotency_key,
                    principal_id=effective_principal_id,
                    crossing_id=envelope.crossing_id,
                    status="completed",
                    result_hash=result_hash,
                    response={"result": result, "status": "success"},
                )
            get_global_metrics().increment("executions_succeeded")
            get_global_metrics().record_latency(f"tool:{envelope.action.tool}", time.time() - t0)
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
            return result, envelope.crossing_id

        elif obs.status == "refuted":
            with contextlib.suppress(Exception):
                self._store.consume_execution_claim(
                    claim.claim_id,
                    executor_principal_id=principal_id,
                    crossing_id=envelope.crossing_id,
                    canonical_hash=envelope.canonical_hash,
                    approval_or_warrant_id=claim.approval_or_warrant_id,
                    result_digest=result_hash,
                    evidence_id=obs.observation_id,
                    verification_status="refuted",
                )
            err_msg = f"Postcondition refuted: claim '{target_claim}' on resource '{target_res}'"
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
            self._store.transition_action_state(
                envelope.crossing_id,
                "failed",
                actor_id=obs.verifier_id,
                reason="postcondition_refuted",
            )
            if idempotency_key:
                self._store.finalize_idempotency_key(
                    idempotency_key=idempotency_key,
                    principal_id=effective_principal_id,
                    crossing_id=envelope.crossing_id,
                    status="failed",
                    response={"error": "postcondition_refuted"},
                )
            get_global_metrics().increment("executions_failed")
            if raise_on_postcondition_failure:
                raise PostconditionFailedError(obs, "failure", err_msg)
            return result, envelope.crossing_id

        else:
            status_label = obs.status
            with contextlib.suppress(Exception):
                self._store.consume_execution_claim(
                    claim.claim_id,
                    executor_principal_id=principal_id,
                    crossing_id=envelope.crossing_id,
                    canonical_hash=envelope.canonical_hash,
                    approval_or_warrant_id=claim.approval_or_warrant_id,
                    result_digest=result_hash,
                    evidence_id=obs.observation_id,
                    verification_status=status_label,
                )
            err_msg = (
                f"Postcondition verification status is '{status_label}' for claim '{target_claim}'"
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
            self._store.transition_action_state(
                envelope.crossing_id,
                "unknown",
                actor_id=obs.verifier_id,
                reason=f"postcondition_{status_label}",
            )
            if idempotency_key:
                self._store.finalize_idempotency_key(
                    idempotency_key=idempotency_key,
                    principal_id=effective_principal_id,
                    crossing_id=envelope.crossing_id,
                    status="reconciliation_required",
                    result_hash=result_hash,
                    response={"status": "unknown", "error": obs.error},
                )
            get_global_metrics().increment("executions_unknown")
            if raise_on_postcondition_failure:
                raise PostconditionFailedError(obs, "unknown", err_msg)
            return result, envelope.crossing_id

    def run(
        self,
        *,
        tool: str,
        verb: str,
        resource: str,
        params: dict[str, Any] | None = None,
        fn: Callable[[ActionEnvelope, Decision], Any] | None = None,
        user_goal: str | None = None,
        declared_by: Literal["human", "agent", "system"] = "agent",
        provenance: list[ProvenanceItem] | tuple[ProvenanceItem, ...] = (),
        warrant: Warrant | dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        verify_postcondition: bool = False,
        postcondition_claim: str | None = None,
        postcondition_expected_digest: str | None = None,
        raise_on_postcondition_failure: bool = False,
        strict_postconditions: bool = False,
        caller_context: CallerContext | None = None,
        raise_on_blocked: bool = True,
    ) -> ExecutionResult:
        """Evaluate, execute via a registered executor (or ``fn``), and return ``ExecutionResult``.

        Preserves all Boundary security invariants (fail-closed evaluation, TOCTOU hash
        checking, warrant enforcement, postcondition binding, and durable receipts).
        """
        norm_tool = tool.strip().lower()
        executor_fn = fn
        if executor_fn is None:
            with self._lock:
                executor_fn = self._executors.get(norm_tool)
        if executor_fn is None:
            avail = ", ".join(self.registered_tools) or "none"
            raise ActentraError(
                f"No executor registered for tool {tool!r} (registered: {avail}). "
                "Register one with boundary.register_fs(...), boundary.register_sqlite(...), "
                "boundary.register_http(...), boundary.register_executor(...), or pass fn=..."
            )

        try:
            raw_result, crossing_id = self._execute_internal(
                tool=tool,
                verb=verb,
                resource=resource,
                params=params,
                fn=executor_fn,
                user_goal=user_goal,
                declared_by=declared_by,
                provenance=provenance,
                warrant=warrant,
                idempotency_key=idempotency_key,
                verify_postcondition=verify_postcondition,
                postcondition_claim=postcondition_claim,
                postcondition_expected_digest=postcondition_expected_digest,
                raise_on_postcondition_failure=raise_on_postcondition_failure,
                strict_postconditions=strict_postconditions,
                caller_context=caller_context,
                auto_default_postcondition=True,
            )
        except ActionBlockedError as exc:
            if raise_on_blocked:
                raise
            dec_rec = self._store.get_decision_receipt(exc.crossing_id)
            return ExecutionResult(
                crossing_id=exc.crossing_id,
                allowed=False,
                verdict=exc.decision.verdict,
                rule_id=exc.decision.rule_id,
                reason=exc.decision.reason,
                status="blocked",
                evidence_status=None,
                verified=False,
                result=None,
                result_hash=None,
                canonical_hash=exc.decision.canonical_hash,
                decision_receipt=dec_rec,
                outcome_receipt=None,
                observation=None,
            )

        dec_rec = self._store.get_decision_receipt(crossing_id)
        out_rec = self._store.get_outcome_receipt(crossing_id)
        obs_list = self._store.list_observations(crossing_id=crossing_id, limit=1)
        obs_rec = obs_list[0] if obs_list else None
        verdict_val = (
            Verdict(dec_rec.verdict) if dec_rec and dec_rec.verdict else Verdict.ALLOW
        )
        ev_status = out_rec.evidence_status if out_rec else None
        out_status = out_rec.status if out_rec and out_rec.status else "success"
        return ExecutionResult(
            crossing_id=crossing_id,
            allowed=True,
            verdict=verdict_val,
            rule_id=dec_rec.rule_id if dec_rec and dec_rec.rule_id else "allow",
            reason=dec_rec.reason if dec_rec and dec_rec.reason else "",
            status=out_status,
            evidence_status=ev_status,
            verified=(out_status == "success" and ev_status == "externally_verified"),
            result=raw_result,
            result_hash=out_rec.result_hash if out_rec else None,
            canonical_hash=dec_rec.canonical_hash if dec_rec else "",
            decision_receipt=dec_rec,
            outcome_receipt=out_rec,
            observation=obs_rec,
        )

    def inspect_crossing(self, crossing_id: str) -> CrossingReceipt:
        """Inspect decision, outcome, observation, envelope, and lifecycle for a crossing."""
        dec_rec = self._store.get_decision_receipt(crossing_id)
        out_rec = self._store.get_outcome_receipt(crossing_id)
        obs_list = self._store.list_observations(crossing_id=crossing_id, limit=1)
        obs_rec = obs_list[0] if obs_list else None
        env_dict = self._store.get_envelope(crossing_id)
        lifecycle = self._store.get_action_lifecycle(crossing_id)
        verified = bool(
            out_rec is not None
            and out_rec.status == "success"
            and out_rec.evidence_status == "externally_verified"
        )
        return CrossingReceipt(
            crossing_id=crossing_id,
            decision=dec_rec,
            outcome=out_rec,
            observation=obs_rec,
            envelope=env_dict,
            lifecycle_state=lifecycle.current_state if lifecycle is not None else None,
            verified=verified,
        )

    def recent_receipts(
        self,
        *,
        limit: int = 20,
        session_id: str | None = None,
        verdict: str | None = None,
    ) -> list[ReceiptRecord]:
        """Return recent receipt records ordered newest-first."""
        records, _total = self._store.query_records(
            limit=limit,
            session_id=session_id,
            verdict=verdict,
        )
        return records

    def verify_receipts(self, *, verify_envelopes: bool = True) -> VerificationResult:
        """Verify SHA-256 hash-chain and envelope integrity of the receipt store."""
        return verify_log(self._store.db_path, verify_envelopes=verify_envelopes)

    def reconcile_outcome(
        self,
        crossing_id: str,
        observation: ObservationRecord | None = None,
    ) -> Any:
        """Safely reconcile an uncertain outcome receipt using independent verification (Phase 5).

        Only outcome receipts in 'unknown' state may be reconciled.
        Terminal 'success' (externally verified) and 'failure' receipts cannot be overwritten.
        """
        outcome = self._store.get_outcome_receipt(crossing_id, apply_reconciliation=False)
        if outcome is None:
            raise ReceiptError(f"No outcome receipt found for crossing '{crossing_id}'")
        if outcome.status != "unknown":
            raise ReceiptError(
                f"Cannot reconcile outcome with terminal status '{outcome.status}' "
                f"(crossing_id='{crossing_id}')"
            )

        env_dict = self._store.get_envelope(crossing_id)
        if env_dict is None:
            raise ReceiptError(f"Envelope for crossing '{crossing_id}' not found")

        obs = observation
        if obs is None:
            if self._verifier is None:
                raise ValueError(
                    "Cannot reconcile outcome: no verifier configured and no observation provided"
                )
            action_data = env_dict.get("action", {})
            res = str(action_data.get("resource", ""))
            verb = str(action_data.get("verb", "other")).lower()
            tool = str(action_data.get("tool", "")).lower()
            params = action_data.get("params") or {}

            # Determine claim & expected digest
            if verb == "write" or tool == "fs.write":
                claim = "digest_match"
                content = params.get("content")
                expected_dig = (
                    compute_content_digest(content) if isinstance(content, (str, bytes)) else None
                )
            elif verb == "delete" or tool == "fs.delete":
                claim = "absent"
                expected_dig = None
            else:
                claim = "exists"
                expected_dig = None

            obs = self._verifier.verify(
                resource=res,
                claim=claim,
                crossing_id=crossing_id,
                expected_digest=expected_dig,
            )

        self._store.record_observation(obs)

        if obs.status == "verified":
            reconciled = self._store.record_reconciliation(
                crossing_id=crossing_id,
                status="success",
                evidence_status="externally_verified",
                reason="reconciled_verified",
                observation=obs,
            )
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
                    "reconciled": True,
                },
                expires_at=obs.expires_at,
            )
            self._store.record_evidence(ev)
            link = CausalLink(
                link_id=generate_link_id(),
                link_version="1",
                source_id=crossing_id,
                source_type="crossing",
                relation="verifies",
                target_id=obs.observation_id,
                target_type="observation",
                created_at=utc_iso(),
            )
            self._store.record_causal_link(link)
            return reconciled
        elif obs.status == "refuted":
            return self._store.record_reconciliation(
                crossing_id=crossing_id,
                status="failure",
                evidence_status="locally_observed",
                reason="reconciled_refuted",
                observation=obs,
            )
        else:
            return self._store.record_reconciliation(
                crossing_id=crossing_id,
                status="unknown",
                evidence_status="stale" if obs.status == "stale" else "unknown",
                reason=f"reconciled_unverified_{obs.status}",
                observation=obs,
            )

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
