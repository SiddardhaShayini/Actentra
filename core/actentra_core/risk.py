"""Deterministic rule-based risk tagger for Actentra."""

from __future__ import annotations

import re

from actentra_core.envelope import ActionEnvelope

_DESTRUCTIVE_SQL_RE = re.compile(
    r"\b(drop|truncate|delete\s+from|alter\s+table|update\s+\S+\s+set)\b",
    re.IGNORECASE,
)
_SENSITIVE_PATH_RE = re.compile(
    r"(\.env|\.ssh|id_rsa|id_ed25519|credentials|secrets|system32|sam\b|\.git/config)",
    re.IGNORECASE,
)
_PII_HINT_RE = re.compile(
    r"\b(ssn|password|secret|token|api_key|credit_card|aadhaar|pan_number)\b",
    re.IGNORECASE,
)
_FINANCIAL_HINT_RE = re.compile(
    r"\b(transfer|refund|payout|invoice|charge|payment|wire)\b",
    re.IGNORECASE,
)


def assess_risk(envelope: ActionEnvelope) -> tuple[str, ...]:
    """Deterministically assign sorted risk tags to an ActionEnvelope."""
    tags: set[str] = set()
    tool = envelope.action.tool
    verb = envelope.action.verb
    resource = envelope.action.resource
    params = envelope.action.params

    if verb == "delete" or tool.endswith(".delete") or tool.endswith(".remove"):
        tags.add("destructive")
        tags.add("irreversible")

    if verb in ("admin", "exec") or tool.startswith(("shell.", "proc.", "iam.")):
        tags.add("privilege-escalation")
        if verb == "exec":
            tags.add("destructive")

    if verb == "network" or tool.startswith(("http.", "net.", "email.", "webhook.")):
        tags.add("external-egress")

    if tool.startswith("sql."):
        query = str(params.get("query", ""))
        if _DESTRUCTIVE_SQL_RE.search(query):
            tags.add("destructive")
            if re.search(r"\b(drop|truncate)\b", query, re.IGNORECASE):
                tags.add("irreversible")
            if re.search(r"\bdelete\s+from\b", query, re.IGNORECASE) and not re.search(
                r"\bwhere\b", query, re.IGNORECASE
            ):
                tags.add("bulk")

    if _SENSITIVE_PATH_RE.search(resource):
        tags.add("privilege-escalation")

    serialized_params = f"{resource} {params}"
    if _PII_HINT_RE.search(serialized_params):
        tags.add("pii-touching")

    if _FINANCIAL_HINT_RE.search(f"{tool} {resource} {params}"):
        tags.add("financial")

    targets = params.get("targets")
    if bool(params.get("recursive")) or (isinstance(targets, list) and len(targets) > 10):
        tags.add("bulk")

    if envelope.max_taint == "untrusted":
        tags.add("untrusted-provenance")

    return tuple(sorted(tags))
