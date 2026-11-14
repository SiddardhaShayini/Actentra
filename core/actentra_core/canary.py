"""Policy Canary diff and regression testing engine.

Evaluates a proposed/candidate policy pack against historical receipt logs to identify
verdict shifts, permission regressions, and escalated approvals before deployment.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from actentra_core.envelope import ProvenanceItem, build_envelope
from actentra_core.policy import PolicyEngine, PolicyPack
from actentra_core.receipts import ReceiptStore
from actentra_core.verdict import VERDICT_PRECEDENCE, Verdict


@dataclass(frozen=True, slots=True)
class CanaryDiffItem:
    crossing_id: str
    session_id: str
    tool: str
    verb: str
    resource: str
    original_verdict: str
    candidate_verdict: str
    original_rule: str
    candidate_rule: str
    delta_type: str  # "more_restrictive", "less_restrictive", "rule_changed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "crossing_id": self.crossing_id,
            "session_id": self.session_id,
            "tool": self.tool,
            "verb": self.verb,
            "resource": self.resource,
            "original_verdict": self.original_verdict,
            "candidate_verdict": self.candidate_verdict,
            "original_rule": self.original_rule,
            "candidate_rule": self.candidate_rule,
            "delta_type": self.delta_type,
        }


@dataclass(frozen=True, slots=True)
class CanarySummary:
    candidate_policy_id: str
    candidate_policy_version: str
    total_evaluated: int
    identical_count: int
    more_restrictive_count: int
    less_restrictive_count: int
    rule_changed_count: int
    diffs: tuple[CanaryDiffItem, ...]
    missing_context_count: int = 0
    fidelity_warnings: tuple[str, ...] = ()

    @property
    def has_regressions(self) -> bool:
        """True if any previously blocked/asked action would now be allowed."""
        return self.less_restrictive_count > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_policy_id": self.candidate_policy_id,
            "candidate_policy_version": self.candidate_policy_version,
            "total_evaluated": self.total_evaluated,
            "identical_count": self.identical_count,
            "more_restrictive_count": self.more_restrictive_count,
            "less_restrictive_count": self.less_restrictive_count,
            "rule_changed_count": self.rule_changed_count,
            "missing_context_count": self.missing_context_count,
            "fidelity_warnings": list(self.fidelity_warnings),
            "has_regressions": self.has_regressions,
            "diffs": [d.to_dict() for d in self.diffs],
        }


def _classify_verdict_shift(orig_v: Verdict, cand_v: Verdict) -> str:
    orig_rank = VERDICT_PRECEDENCE.get(orig_v, 0)
    cand_rank = VERDICT_PRECEDENCE.get(cand_v, 0)
    if cand_rank > orig_rank:
        return "more_restrictive"
    if cand_rank < orig_rank:
        return "less_restrictive"
    return "rule_changed"


def run_policy_canary(
    candidate_policy: PolicyPack,
    receipts_db: str | Path,
    *,
    limit: int | None = None,
) -> CanarySummary:
    """Replay historical decision receipts against a candidate policy to detect verdict shifts."""
    store = ReceiptStore(receipts_db)
    records = store.iter_records()
    engine = PolicyEngine(candidate_policy)

    decisions = [r for r in records if r.record_type == "decision"]
    if limit is not None and len(decisions) > limit:
        decisions = decisions[-limit:]

    diffs: list[CanaryDiffItem] = []
    identical = 0
    more_rest = 0
    less_rest = 0
    rule_changed = 0
    missing_context = 0

    for rec in decisions:
        orig_verdict_str = (rec.verdict or "deny").lower()
        orig_rule = rec.rule_id or ""

        env_dict = store.get_envelope(rec.crossing_id)
        if env_dict is None:
            missing_context += 1
            diffs.append(
                CanaryDiffItem(
                    crossing_id=rec.crossing_id,
                    session_id=rec.session_id,
                    tool="unknown",
                    verb="unknown",
                    resource="unknown",
                    original_verdict=orig_verdict_str,
                    candidate_verdict="missing_context",
                    original_rule=orig_rule,
                    candidate_rule="none",
                    delta_type="missing_context",
                )
            )
            continue

        action_data = env_dict.get("action") or {}
        agent_data = env_dict.get("agent") or {}
        intent_data = env_dict.get("intent") or {}

        tool = str(action_data.get("tool", ""))
        verb = str(action_data.get("verb", "other"))
        resource = str(action_data.get("resource", ""))
        params = action_data.get("params") or {}
        agent_id = str(agent_data.get("id", "canary-agent"))
        framework = str(agent_data.get("framework", "custom"))
        model = str(agent_data.get("model", "unknown"))
        idempotency_key = action_data.get("idempotency_key")
        user_goal = intent_data.get("user_goal")
        raw_declared_by = intent_data.get("declared_by", "agent")
        declared_by: Literal["human", "agent", "system"] = (
            raw_declared_by
            if raw_declared_by in ("human", "agent", "system")
            else "agent"
        )

        prov_items = [
            ProvenanceItem(source=item["source"], trust=item["trust"])
            for item in env_dict.get("provenance", [])
            if isinstance(item, dict) and "source" in item and "trust" in item
        ]

        try:
            envelope = build_envelope(
                tool=tool,
                verb=verb,
                resource=resource,
                params=params,
                session_id=rec.session_id,
                agent_id=agent_id,
                framework=framework,
                model=model,
                user_goal=user_goal,
                declared_by=declared_by,
                provenance=prov_items,
                idempotency_key=idempotency_key,
                crossing_id=rec.crossing_id,
                ts=env_dict.get("ts", rec.ts),
            )
        except Exception:  # noqa: S112
            missing_context += 1
            diffs.append(
                CanaryDiffItem(
                    crossing_id=rec.crossing_id,
                    session_id=rec.session_id,
                    tool=tool or "invalid",
                    verb=verb or "invalid",
                    resource=resource or "invalid",
                    original_verdict=orig_verdict_str,
                    candidate_verdict="schema_error",
                    original_rule=orig_rule,
                    candidate_rule="none",
                    delta_type="missing_context",
                )
            )
            continue

        # Verify envelope action hash matches the decision receipt's canonical_hash
        if envelope.canonical_hash != rec.canonical_hash:
            missing_context += 1
            diffs.append(
                CanaryDiffItem(
                    crossing_id=rec.crossing_id,
                    session_id=rec.session_id,
                    tool=tool,
                    verb=verb,
                    resource=resource,
                    original_verdict=orig_verdict_str,
                    candidate_verdict="integrity_mismatch",
                    original_rule=orig_rule,
                    candidate_rule="none",
                    delta_type="missing_context",
                )
            )
            continue

        hist_time: float | None = None
        try:
            ts_raw = env_dict.get("ts") or rec.ts
            ts_iso = str(ts_raw).replace("Z", "+00:00")
            hist_time = datetime.fromisoformat(ts_iso).timestamp()
        except Exception:
            hist_time = None

        cand_dec = engine.evaluate(envelope, record_rate_limit=True, timestamp=hist_time)
        if cand_dec.verdict.permits_execution:
            engine.budget_tracker.record_usage(envelope)

        cand_verdict_str = cand_dec.verdict.value

        try:
            orig_v = Verdict(orig_verdict_str)
        except ValueError:
            orig_v = Verdict.DENY

        if orig_verdict_str == cand_verdict_str:
            if orig_rule == cand_dec.rule_id:
                identical += 1
            else:
                rule_changed += 1
                diffs.append(
                    CanaryDiffItem(
                        crossing_id=rec.crossing_id,
                        session_id=rec.session_id,
                        tool=tool,
                        verb=verb,
                        resource=resource,
                        original_verdict=orig_verdict_str,
                        candidate_verdict=cand_verdict_str,
                        original_rule=orig_rule,
                        candidate_rule=cand_dec.rule_id,
                        delta_type="rule_changed",
                    )
                )
        else:
            delta = _classify_verdict_shift(orig_v, cand_dec.verdict)
            if delta == "more_restrictive":
                more_rest += 1
            else:
                less_rest += 1

            diffs.append(
                CanaryDiffItem(
                    crossing_id=rec.crossing_id,
                    session_id=rec.session_id,
                    tool=tool,
                    verb=verb,
                    resource=resource,
                    original_verdict=orig_verdict_str,
                    candidate_verdict=cand_verdict_str,
                    original_rule=orig_rule,
                    candidate_rule=cand_dec.rule_id,
                    delta_type=delta,
                )
            )

    warnings: list[str] = []
    if missing_context > 0:
        warnings.append(
            f"{missing_context} historical decision(s) had missing or "
            "unverifiable envelope context; canary evaluation is advisory."
        )

    return CanarySummary(
        candidate_policy_id=candidate_policy.policy_id,
        candidate_policy_version=candidate_policy.policy_version,
        total_evaluated=len(decisions),
        identical_count=identical,
        more_restrictive_count=more_rest,
        less_restrictive_count=less_rest,
        rule_changed_count=rule_changed,
        diffs=tuple(diffs),
        missing_context_count=missing_context,
        fidelity_warnings=tuple(warnings),
    )
