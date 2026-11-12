"""Verdict and decision types for Actentra."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Verdict(StrEnum):
    """Deterministic authorization verdict produced by the policy engine."""

    ALLOW = "allow"
    ALLOW_WITH_CONSTRAINTS = "allow_with_constraints"
    ASK = "ask"
    DENY = "deny"
    HOLD = "hold"

    @property
    def permits_execution(self) -> bool:
        """Return True only when execution may proceed directly."""
        return self in (Verdict.ALLOW, Verdict.ALLOW_WITH_CONSTRAINTS)


# Precedence order for deny-overrides evaluation (highest severity first).
VERDICT_PRECEDENCE: dict[Verdict, int] = {
    Verdict.DENY: 5,
    Verdict.HOLD: 4,
    Verdict.ASK: 3,
    Verdict.ALLOW_WITH_CONSTRAINTS: 2,
    Verdict.ALLOW: 1,
}


@dataclass(frozen=True, slots=True)
class Decision:
    """Explainable authorization outcome for an ActionEnvelope."""

    verdict: Verdict
    rule_id: str
    reason: str
    policy_version: str
    canonical_hash: str
    risk_tags: tuple[str, ...] = ()
    constraints: dict[str, Any] = field(default_factory=dict)
    shadow: bool = False
    would_verdict: Verdict | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize decision into a JSON-compatible dictionary."""
        data: dict[str, Any] = {
            "verdict": self.verdict.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "canonical_hash": self.canonical_hash,
            "risk_tags": list(self.risk_tags),
            "constraints": dict(self.constraints),
            "shadow": self.shadow,
        }
        if self.would_verdict is not None:
            data["would_verdict"] = self.would_verdict.value
        return data
