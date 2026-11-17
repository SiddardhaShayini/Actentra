"""Deterministic YAML policy engine for Actentra (deny-overrides)."""

from __future__ import annotations

import fnmatch
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from actentra_core.budgets import SessionBudgetConfig, SessionBudgetTracker
from actentra_core.canonicalize import (
    CanonicalizationError,
    hash_canonical,
    match_resource_pattern,
)
from actentra_core.envelope import ActionEnvelope
from actentra_core.risk import assess_risk
from actentra_core.verdict import VERDICT_PRECEDENCE, Decision, Verdict

_TOP_LEVEL_KEYS = frozenset(
    {"version", "policy_id", "mode", "defaults", "limits", "budgets", "rules"}
)
_DEFAULT_KEYS = frozenset({"verdict", "reason"})
_LIMIT_KEYS = frozenset({"id", "scope", "max_actions_per_minute"})
_RULE_KEYS = frozenset({"id", "match", "verdict", "constraints", "reason"})
_MATCH_KEYS = frozenset({"tool", "verb", "resource", "agent_id", "taint", "risk_any", "risk_all"})
_VALID_MODES = frozenset({"enforce", "shadow"})
_VALID_DEFAULT_VERDICTS = frozenset({Verdict.DENY, Verdict.HOLD})
_VALID_TRUST = frozenset({"trusted", "untrusted", "unknown"})
_MAX_TRACKED_SESSIONS = 4096


class PolicyValidationError(ValueError):
    """Raised when a policy file fails schema or semantic validation."""


@dataclass(frozen=True, slots=True)
class RateLimit:
    id: str
    scope: str
    max_actions_per_minute: int


@dataclass(frozen=True, slots=True)
class RuleMatch:
    tool: str | None = None
    verbs: tuple[str, ...] = ()
    resource: str | None = None
    agent_id: str | None = None
    taint: str | None = None
    risk_any: tuple[str, ...] = ()
    risk_all: tuple[str, ...] = ()

    def matches(self, envelope: ActionEnvelope, risk_tags: tuple[str, ...]) -> bool:
        if self.tool is not None and not fnmatch.fnmatchcase(
            envelope.action.tool, self.tool.lower()
        ):
            return False
        if self.verbs and envelope.action.verb not in self.verbs:
            return False
        if self.agent_id is not None and not fnmatch.fnmatchcase(envelope.agent.id, self.agent_id):
            return False
        if self.taint is not None and envelope.max_taint != self.taint:
            return False
        if self.risk_any:
            tag_set = set(risk_tags)
            if not any(tag in tag_set for tag in self.risk_any):
                return False
        if self.risk_all:
            tag_set = set(risk_tags)
            if not all(tag in tag_set for tag in self.risk_all):
                return False
        if self.resource is not None:
            try:
                if not match_resource_pattern(self.resource, envelope.action.resource):
                    return False
            except CanonicalizationError:
                return False
        return True


@dataclass(frozen=True, slots=True)
class PolicyRule:
    id: str
    match: RuleMatch
    verdict: Verdict
    reason: str = ""
    constraints: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PolicyPack:
    version: int
    policy_id: str
    mode: str
    default_verdict: Verdict
    default_reason: str
    limits: tuple[RateLimit, ...]
    rules: tuple[PolicyRule, ...]
    policy_hash: str
    budgets: SessionBudgetConfig | None = None

    @property
    def policy_version(self) -> str:
        return f"v{self.version}:{self.policy_hash[:19]}"


def _reject_unknown_keys(mapping: dict[str, Any], allowed: frozenset[str], context: str) -> None:
    unknown = set(mapping.keys()) - allowed
    if unknown:
        raise PolicyValidationError(f"Unknown keys in {context}: {sorted(unknown)}")


def parse_policy_dict(raw: Any) -> PolicyPack:
    """Validate and parse a policy dictionary into an immutable PolicyPack."""
    if not isinstance(raw, dict):
        raise PolicyValidationError("Policy root must be a YAML mapping")
    _reject_unknown_keys(raw, _TOP_LEVEL_KEYS, "policy root")

    version = raw.get("version")
    if version != 1:
        raise PolicyValidationError(f"Unsupported policy version: {version!r} (expected 1)")

    policy_id = str(raw.get("policy_id", "default-policy")).strip()
    if not policy_id:
        raise PolicyValidationError("policy_id must be non-empty")

    mode = str(raw.get("mode", "enforce")).strip().lower()
    if mode not in _VALID_MODES:
        raise PolicyValidationError(f"Invalid policy mode {mode!r}; expected enforce or shadow")

    defaults_raw = raw.get("defaults")
    if not isinstance(defaults_raw, dict):
        raise PolicyValidationError("defaults must be a mapping")
    _reject_unknown_keys(defaults_raw, _DEFAULT_KEYS, "defaults")
    raw_default_verdict = str(defaults_raw.get("verdict", "")).lower()
    try:
        default_verdict = Verdict(raw_default_verdict)
    except ValueError as exc:
        raise PolicyValidationError(f"Invalid defaults.verdict: {raw_default_verdict!r}") from exc
    if default_verdict not in _VALID_DEFAULT_VERDICTS:
        raise PolicyValidationError("defaults.verdict must fail closed ('deny' or 'hold')")
    default_reason = str(defaults_raw.get("reason", "Denied by default policy"))

    limits_raw = raw.get("limits", [])
    if not isinstance(limits_raw, list):
        raise PolicyValidationError("limits must be a list")
    limits: list[RateLimit] = []
    seen_limit_ids: set[str] = set()
    for idx, item in enumerate(limits_raw):
        if not isinstance(item, dict):
            raise PolicyValidationError(f"limits[{idx}] must be a mapping")
        _reject_unknown_keys(item, _LIMIT_KEYS, f"limits[{idx}]")
        lid = str(item.get("id", "")).strip()
        if not lid or lid in seen_limit_ids:
            raise PolicyValidationError(f"limits[{idx}].id must be non-empty and unique")
        seen_limit_ids.add(lid)
        scope = str(item.get("scope", "")).strip().lower()
        if scope not in ("session", "global"):
            raise PolicyValidationError(f"limits[{idx}].scope must be 'session' or 'global'")
        cap = item.get("max_actions_per_minute")
        if not isinstance(cap, int) or isinstance(cap, bool) or cap < 1:
            raise PolicyValidationError(
                f"limits[{idx}].max_actions_per_minute must be a positive integer"
            )
        limits.append(RateLimit(id=lid, scope=scope, max_actions_per_minute=cap))

    rules_raw = raw.get("rules")
    if not isinstance(rules_raw, list):
        raise PolicyValidationError("rules must be a list")
    rules: list[PolicyRule] = []
    seen_rule_ids: set[str] = set()
    for idx, r_raw in enumerate(rules_raw):
        if not isinstance(r_raw, dict):
            raise PolicyValidationError(f"rules[{idx}] must be a mapping")
        _reject_unknown_keys(r_raw, _RULE_KEYS, f"rules[{idx}]")
        rid = str(r_raw.get("id", "")).strip()
        if not rid or rid in seen_rule_ids:
            raise PolicyValidationError(f"rules[{idx}].id must be non-empty and unique")
        seen_rule_ids.add(rid)

        match_raw = r_raw.get("match")
        if not isinstance(match_raw, dict) or not match_raw:
            raise PolicyValidationError(f"rules[{idx}].match must be a non-empty mapping")
        _reject_unknown_keys(match_raw, _MATCH_KEYS, f"rules[{idx}].match")

        verbs_raw = match_raw.get("verb")
        verbs: tuple[str, ...] = ()
        if isinstance(verbs_raw, str):
            verbs = (verbs_raw.strip().lower(),)
        elif isinstance(verbs_raw, list) and verbs_raw:
            verbs = tuple(str(v).strip().lower() for v in verbs_raw)
        elif verbs_raw is not None:
            raise PolicyValidationError(
                f"rules[{idx}].match.verb must be a string or non-empty list"
            )

        taint = match_raw.get("taint")
        if taint is not None:
            taint = str(taint).strip().lower()
            if taint not in _VALID_TRUST:
                raise PolicyValidationError(f"rules[{idx}].match.taint invalid: {taint!r}")

        risk_any_raw = match_raw.get("risk_any", [])
        if risk_any_raw and not isinstance(risk_any_raw, list):
            raise PolicyValidationError(f"rules[{idx}].match.risk_any must be a list")
        risk_all_raw = match_raw.get("risk_all", [])
        if risk_all_raw and not isinstance(risk_all_raw, list):
            raise PolicyValidationError(f"rules[{idx}].match.risk_all must be a list")

        verdict_raw = str(r_raw.get("verdict", "")).strip().lower()
        try:
            verdict = Verdict(verdict_raw)
        except ValueError as exc:
            raise PolicyValidationError(f"rules[{idx}].verdict invalid: {verdict_raw!r}") from exc

        constraints = r_raw.get("constraints") or {}
        if not isinstance(constraints, dict):
            raise PolicyValidationError(f"rules[{idx}].constraints must be a mapping")

        resource_pat = match_raw.get("resource")
        if resource_pat is not None and not isinstance(resource_pat, str):
            raise PolicyValidationError(f"rules[{idx}].match.resource must be a string")

        rule_match = RuleMatch(
            tool=str(match_raw["tool"]).strip() if "tool" in match_raw else None,
            verbs=verbs,
            resource=resource_pat.strip() if resource_pat is not None else None,
            agent_id=str(match_raw["agent_id"]).strip() if "agent_id" in match_raw else None,
            taint=taint,
            risk_any=tuple(str(x).strip().lower() for x in risk_any_raw),
            risk_all=tuple(str(x).strip().lower() for x in risk_all_raw),
        )
        rules.append(
            PolicyRule(
                id=rid,
                match=rule_match,
                verdict=verdict,
                reason=str(r_raw.get("reason", f"Matched policy rule {rid}")),
                constraints=dict(constraints),
            )
        )

    budgets_raw = raw.get("budgets")
    budgets = SessionBudgetConfig.from_dict(budgets_raw) if budgets_raw else None

    policy_hash = hash_canonical(raw)
    return PolicyPack(
        version=version,
        policy_id=policy_id,
        mode=mode,
        default_verdict=default_verdict,
        default_reason=default_reason,
        limits=tuple(limits),
        rules=tuple(rules),
        policy_hash=policy_hash,
        budgets=budgets,
    )


def load_policy_yaml(yaml_text: str) -> PolicyPack:
    """Parse and validate a YAML policy string."""
    try:
        loaded = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        raise PolicyValidationError(f"YAML syntax error: {exc}") from exc
    return parse_policy_dict(loaded)


def load_policy_file(path: str | Path) -> PolicyPack:
    """Load and validate a policy YAML file from disk."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyValidationError(f"Unable to read policy file {path}: {exc}") from exc
    return load_policy_yaml(text)


class PolicyEngine:
    """Deterministic deny-overrides policy evaluator with bounded rate limits."""

    def __init__(
        self,
        policy: PolicyPack,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._policy = policy
        self._clock = clock or time.monotonic
        self._frozen = False
        self._buckets: dict[tuple[str, str], deque[float]] = {}
        self._budget_tracker = SessionBudgetTracker(policy.budgets)

    @property
    def policy(self) -> PolicyPack:
        return self._policy

    @property
    def budget_tracker(self) -> SessionBudgetTracker:
        return self._budget_tracker

    @property
    def frozen(self) -> bool:
        return self._frozen

    def freeze(self) -> None:
        """Activate kill switch: deny everything except allow-listed read-only actions."""
        self._frozen = True

    def unfreeze(self) -> None:
        """Deactivate kill switch."""
        self._frozen = False

    def _check_rate_limits(
        self,
        envelope: ActionEnvelope,
        *,
        record: bool = True,
        timestamp: float | None = None,
    ) -> PolicyRule | None:
        if not self._policy.limits:
            return None
        now = timestamp if timestamp is not None else self._clock()
        cutoff = now - 60.0
        for limit in self._policy.limits:
            scope_key = "global" if limit.scope == "global" else envelope.session_id
            bucket_key = (limit.id, scope_key)
            if bucket_key not in self._buckets and len(self._buckets) >= _MAX_TRACKED_SESSIONS:
                # Evict oldest inserted key to keep memory strictly bounded.
                oldest = next(iter(self._buckets))
                del self._buckets[oldest]
            q = self._buckets.setdefault(bucket_key, deque())
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= limit.max_actions_per_minute:
                return PolicyRule(
                    id=f"limit:{limit.id}",
                    match=RuleMatch(),
                    verdict=Verdict.DENY,
                    reason=(
                        f"Rate limit '{limit.id}' exceeded "
                        f"({limit.max_actions_per_minute}/min, scope={limit.scope})"
                    ),
                )
            if record:
                q.append(now)
        return None

    def evaluate(
        self,
        envelope: ActionEnvelope,
        *,
        record_rate_limit: bool = True,
        timestamp: float | None = None,
    ) -> Decision:
        """Evaluate an ActionEnvelope deterministically and return an explainable Decision.

        When record_rate_limit is False (such as in simulations or dry-run previews),
        rate limit consumption is not recorded to avoid mutating real-action allowances.
        When timestamp is provided (such as in canary historical replays), the rate-limit
        window evaluates against that specific point in time rather than current system clock.
        """
        risk_tags = assess_risk(envelope)

        if self._frozen and envelope.action.verb != "read":
            return Decision(
                verdict=Verdict.DENY,
                rule_id="kill-switch:frozen",
                reason=(
                    "System is frozen by kill switch; "
                    "only read-only allow-listed actions are permitted"
                ),
                policy_version=self._policy.policy_version,
                canonical_hash=envelope.canonical_hash,
                risk_tags=risk_tags,
                shadow=False,
            )

        limit_hit = self._check_rate_limits(envelope, record=record_rate_limit, timestamp=timestamp)
        if limit_hit is not None:
            return self._finalize_decision(
                evaluated_verdict=limit_hit.verdict,
                rule_id=limit_hit.id,
                reason=limit_hit.reason,
                constraints={},
                envelope=envelope,
                risk_tags=risk_tags,
            )

        budget_hit = self._budget_tracker.check_budget(envelope)
        if budget_hit is not None:
            combined_tags = tuple(sorted(set(risk_tags) | set(budget_hit.risk_tags)))
            return self._finalize_decision(
                evaluated_verdict=budget_hit.verdict,
                rule_id=budget_hit.rule_id,
                reason=budget_hit.reason,
                constraints={},
                envelope=envelope,
                risk_tags=combined_tags,
            )

        winning_rule: PolicyRule | None = None
        winning_prec = 0
        for rule in self._policy.rules:
            if rule.match.matches(envelope, risk_tags):
                prec = VERDICT_PRECEDENCE[rule.verdict]
                if prec > winning_prec:
                    winning_rule = rule
                    winning_prec = prec

        if winning_rule is None:
            return self._finalize_decision(
                evaluated_verdict=self._policy.default_verdict,
                rule_id="default",
                reason=self._policy.default_reason,
                constraints={},
                envelope=envelope,
                risk_tags=risk_tags,
            )

        if (
            self._frozen
            and winning_rule.verdict.permits_execution
            and envelope.action.verb != "read"
        ):
            return Decision(
                verdict=Verdict.DENY,
                rule_id="kill-switch:frozen",
                reason="System is frozen by kill switch",
                policy_version=self._policy.policy_version,
                canonical_hash=envelope.canonical_hash,
                risk_tags=risk_tags,
                shadow=False,
            )

        return self._finalize_decision(
            evaluated_verdict=winning_rule.verdict,
            rule_id=winning_rule.id,
            reason=winning_rule.reason,
            constraints=winning_rule.constraints,
            envelope=envelope,
            risk_tags=risk_tags,
        )

    def _finalize_decision(
        self,
        *,
        evaluated_verdict: Verdict,
        rule_id: str,
        reason: str,
        constraints: dict[str, Any],
        envelope: ActionEnvelope,
        risk_tags: tuple[str, ...],
    ) -> Decision:
        if self._policy.mode == "shadow":
            return Decision(
                verdict=Verdict.ALLOW,
                rule_id=rule_id,
                reason=f"[SHADOW] {reason}",
                policy_version=self._policy.policy_version,
                canonical_hash=envelope.canonical_hash,
                risk_tags=risk_tags,
                constraints=constraints,
                shadow=True,
                would_verdict=evaluated_verdict,
            )
        return Decision(
            verdict=evaluated_verdict,
            rule_id=rule_id,
            reason=reason,
            policy_version=self._policy.policy_version,
            canonical_hash=envelope.canonical_hash,
            risk_tags=risk_tags,
            constraints=constraints,
            shadow=False,
            would_verdict=None,
        )


class PolicyStore:
    """Holds the active PolicyPack and guarantees last-known-good on reload failure (I6)."""

    def __init__(self, initial: PolicyPack) -> None:
        self._current = initial
        self._engine = PolicyEngine(initial)

    @property
    def current(self) -> PolicyPack:
        return self._current

    @property
    def engine(self) -> PolicyEngine:
        return self._engine

    def reload_yaml(self, yaml_text: str) -> PolicyPack:
        """Validate new policy first; replace active engine only if validation succeeds."""
        candidate = load_policy_yaml(yaml_text)
        frozen = self._engine.frozen
        new_engine = PolicyEngine(candidate)
        if frozen:
            new_engine.freeze()
        self._current = candidate
        self._engine = new_engine
        return candidate

    def reload_file(self, path: str | Path) -> PolicyPack:
        candidate = load_policy_file(path)
        frozen = self._engine.frozen
        new_engine = PolicyEngine(candidate)
        if frozen:
            new_engine.freeze()
        self._current = candidate
        self._engine = new_engine
        return candidate


def lint_policy(pack: PolicyPack) -> list[str]:
    """Return non-fatal static lint warnings for a validated PolicyPack."""
    warnings: list[str] = []
    if pack.mode == "shadow":
        warnings.append("Policy is in 'shadow' mode and will not block actions.")
    if not pack.limits:
        warnings.append("No rate limits configured; consider adding a session rate limit.")

    for idx, rule in enumerate(pack.rules):
        if (
            rule.verdict.permits_execution
            and rule.match.tool is None
            and rule.match.resource is None
        ):
            warnings.append(
                f"Rule '{rule.id}' permits execution without scoping 'tool' or 'resource'."
            )
        if (
            rule.verdict.permits_execution
            and rule.match.tool == "*"
            and rule.match.resource is None
        ):
            warnings.append(f"Rule '{rule.id}' uses wildcard tool '*' without resource scope.")
        if not rule.reason or rule.reason.startswith("Matched policy rule "):
            warnings.append(f"Rule '{rule.id}' has no explicit human-readable 'reason'.")

        # Detect simple duplicate/shadowed matchers at equal or lower precedence.
        for earlier in pack.rules[:idx]:
            if earlier.match == rule.match and (
                VERDICT_PRECEDENCE[earlier.verdict] >= VERDICT_PRECEDENCE[rule.verdict]
            ):
                warnings.append(
                    f"Rule '{rule.id}' is shadowed by earlier rule '{earlier.id}' "
                    "with an identical matcher."
                )
    return warnings
