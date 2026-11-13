"""Typed Application Services layer for Actentra.

Unifies core deterministic kernel, executors, persistent receipts, approvals,
canary simulations, and audit reporting for both the CLI and Local Web UI.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from actentra.boundary import ActionBlockedError, Boundary
from actentra_core.canonicalize import hash_canonical
from actentra_core.envelope import (
    ActionEnvelope,
    EnvelopeError,
    ProvenanceItem,
    build_envelope,
    compute_action_hash,
)
from actentra_core.policy import lint_policy, load_policy_yaml
from actentra_core.receipts import GENESIS_HASH, verify_log
from actentra_core.verdict import Decision, Verdict
from actentra_executors.fs import LocalFSExecutor
from actentra_executors.http import ScopedHTTPExecutor
from actentra_executors.sqlite import ScopedSQLiteExecutor

ToolExecutorCallable = Callable[[ActionEnvelope, Decision], Any]


class ExecutorRegistry:
    """Registry of scoped action executors available for dispatch."""

    def __init__(self) -> None:
        self._executors: dict[str, ToolExecutorCallable] = {}

    def register(self, tool_name: str, fn: ToolExecutorCallable) -> None:
        """Register a callable executor for a specific tool name or prefix."""
        self._executors[tool_name.strip().lower()] = fn

    def register_fs(self, workspace_root: str | Path) -> None:
        """Register Scoped Filesystem executor for fs.* tools."""
        executor = LocalFSExecutor(workspace_root)
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
        approval_ttl_seconds: float = 300.0,
    ) -> None:
        self.boundary = boundary
        self.registry = executor_registry or ExecutorRegistry()
        self.approval_ttl_seconds = approval_ttl_seconds

    # --- 1. Health & Status ---

    def get_health(self, *, full_verify: bool = False) -> dict[str, Any]:
        """Return runtime health, policy state, and receipt store integrity."""
        db_path = self.boundary.receipt_store.db_path
        pending_list = self.boundary.receipt_store.list_pending_approvals(status="pending")
        if full_verify:
            vr = verify_log(db_path)
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
    ) -> dict[str, Any]:
        """Propose, canonicalize, evaluate, and conditionally execute an action."""
        session_id = str(data.get("session_id", "default"))
        prov_items = [
            ProvenanceItem(source=p["source"], trust=p["trust"])
            for p in data.get("provenance", [])
            if isinstance(p, dict) and "source" in p and "trust" in p
        ]
        # Propagate session taint across gateway crossings (Finding 5)
        if not prov_items and self.boundary.get_session_taint(session_id) == "untrusted":
            prov_items.append(ProvenanceItem(source="session", trust="untrusted"))

        try:
            envelope = build_envelope(
                tool=str(data.get("tool", "")),
                verb=str(data.get("verb", "other")),
                resource=str(data.get("resource", "")),
                params=data.get("params") or {},
                session_id=session_id,
                agent_id=str(data.get("agent_id", "http-client")),
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
                    resp["outcome"] = {"status": "success", "result": exec_result}
                except Exception as exc:
                    resp["outcome"] = {"status": "failure", "error": type(exc).__name__}
            else:
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
        )
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
    ) -> dict[str, Any]:
        """Resolve a pending crossing (approve or deny) with optional execution dispatch."""
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
            exec_res = self.execute_approved_crossing(crossing_id)
            resp["execution"] = exec_res

        return resp

    def execute_approved_crossing(self, crossing_id: str) -> dict[str, Any]:
        """Execute a previously approved crossing through registered executor."""
        p = self.boundary.receipt_store.get_pending_approval(crossing_id)
        if p is None:
            return {"error": f"Crossing '{crossing_id}' not found"}
        if p.status != "approved":
            return {
                "error": f"Crossing '{crossing_id}' is not in approved state (status={p.status})"
            }

        raw_env = self.boundary.receipt_store.get_envelope(crossing_id)
        if raw_env is None:
            return {"error": f"Context envelope for '{crossing_id}' missing from store"}

        action_data = raw_env.get("action") or {}
        agent_data = raw_env.get("agent") or {}
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

        decision = self.boundary.engine.evaluate(envelope)
        if decision.verdict == Verdict.ASK and self.boundary._has_valid_approval(envelope):
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
        # Finding 8: Prevent duplicate outcome reporting
        if self.boundary.receipt_store.has_outcome_receipt(crossing_id):
            return {"error": f"Outcome already recorded for crossing '{crossing_id}'"}

        # Finding 8: Verify corresponding decision receipt exists
        dec_rec = self.boundary.receipt_store.get_decision_receipt(crossing_id)
        if dec_rec is None:
            return {"error": f"No decision receipt found for crossing '{crossing_id}'"}

        # Finding 8: Verify that the decision permitted execution
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

        rec = self.boundary.receipt_store.record_outcome(
            crossing_id=crossing_id,
            session_id=raw_env["session_id"],
            canonical_hash=raw_env["canonical_hash"],
            policy_version=self.boundary.engine.policy.policy_version,
            status=status,
            result_hash=result_hash,
            error=error,
        )
        return {"status": "recorded", "outcome_seq": rec.seq, "entry_hash": rec.entry_hash}

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

    def verify_audit_log(self) -> dict[str, Any]:
        """Verify receipt log hash-chain integrity."""
        vr = verify_log(self.boundary.receipt_store.db_path)
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
        }
        if out_path is not None:
            dest = Path(out_path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("w", encoding="utf-8") as fh:
                json.dump(bundle, fh, indent=2, ensure_ascii=False)
            bundle["exported_file"] = str(dest.resolve())
        return bundle
