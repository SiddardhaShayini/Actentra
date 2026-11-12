"""Action Envelope builder and canonical contract for Actentra."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from actentra_core.canonicalize import (
    CanonicalizationError,
    canonicalize_resource,
    canonicalize_unicode,
    hash_canonical,
)

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_VALID_VERBS: frozenset[str] = frozenset(
    {"read", "write", "delete", "exec", "network", "admin", "other"}
)
_VALID_TRUST: frozenset[str] = frozenset({"trusted", "untrusted", "unknown"})
_VALID_DECLARED_BY: frozenset[str] = frozenset({"human", "agent", "system"})


class EnvelopeError(ValueError):
    """Raised when an Action Envelope cannot be constructed or validated."""


def generate_crossing_id() -> str:
    """Generate a 26-character Crockford Base32 ULID without external deps."""
    ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand_bytes = os.urandom(10)
    value = (ts_ms << 80) | int.from_bytes(rand_bytes, "big")
    chars = ["0"] * 26
    for i in range(25, -1, -1):
        chars[i] = _CROCKFORD[value & 0x1F]
        value >>= 5
    return "".join(chars)


def utc_now_iso() -> str:
    """Return current UTC timestamp formatted in ISO-8601 Z format."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class AgentInfo:
    id: str
    framework: str = "custom"
    model: str = "unknown"

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "framework": self.framework,
            "model": self.model,
        }


@dataclass(frozen=True, slots=True)
class IntentInfo:
    user_goal: str
    declared_by: Literal["human", "agent", "system"] = "agent"

    def to_dict(self) -> dict[str, str]:
        return {
            "user_goal": self.user_goal,
            "declared_by": self.declared_by,
        }


@dataclass(frozen=True, slots=True)
class ProvenanceItem:
    source: str
    trust: Literal["trusted", "untrusted", "unknown"] = "unknown"

    def to_dict(self) -> dict[str, str]:
        return {
            "source": self.source,
            "trust": self.trust,
        }


@dataclass(frozen=True, slots=True)
class ActionSpec:
    tool: str
    verb: str
    resource: str
    params: dict[str, Any] = field(default_factory=dict)
    idempotency_key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "verb": self.verb,
            "resource": self.resource,
            "params": dict(self.params),
            "idempotency_key": self.idempotency_key,
        }


@dataclass(frozen=True, slots=True)
class ActionEnvelope:
    """Canonicalized, hashed action request evaluated by Actentra."""

    envelope_version: str
    crossing_id: str
    session_id: str
    agent: AgentInfo
    action: ActionSpec
    canonical_hash: str
    ts: str
    intent: IntentInfo | None = None
    provenance: tuple[ProvenanceItem, ...] = ()

    @property
    def max_taint(self) -> str:
        """Return highest-concern trust label across provenance entries."""
        if not self.provenance:
            return "trusted"
        trusts = {item.trust for item in self.provenance}
        if "untrusted" in trusts:
            return "untrusted"
        if "unknown" in trusts:
            return "unknown"
        return "trusted"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "envelope_version": self.envelope_version,
            "crossing_id": self.crossing_id,
            "session_id": self.session_id,
            "agent": self.agent.to_dict(),
            "action": self.action.to_dict(),
            "provenance": [p.to_dict() for p in self.provenance],
            "canonical_hash": self.canonical_hash,
            "ts": self.ts,
        }
        if self.intent is not None:
            data["intent"] = self.intent.to_dict()
        return data


def _canonicalize_params(value: Any) -> Any:
    if isinstance(value, str):
        return canonicalize_unicode(value, allow_newlines=True)
    if isinstance(value, dict):
        return {
            canonicalize_unicode(str(k)): _canonicalize_params(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_canonicalize_params(item) for item in value]
    return value


def compute_action_hash(
    *,
    envelope_version: str,
    session_id: str,
    agent_id: str,
    action: ActionSpec,
) -> str:
    """Compute the canonical SHA-256 hash used for approval binding and TOCTOU checks."""
    payload = {
        "envelope_version": envelope_version,
        "session_id": session_id,
        "agent_id": agent_id,
        "action": action.to_dict(),
    }
    return hash_canonical(payload)


def build_envelope(
    *,
    tool: str,
    verb: str,
    resource: str,
    params: dict[str, Any] | None = None,
    session_id: str = "default",
    agent_id: str = "default-agent",
    framework: str = "custom",
    model: str = "unknown",
    user_goal: str | None = None,
    declared_by: Literal["human", "agent", "system"] = "agent",
    provenance: list[ProvenanceItem] | tuple[ProvenanceItem, ...] = (),
    idempotency_key: str | None = None,
    crossing_id: str | None = None,
    ts: str | None = None,
) -> ActionEnvelope:
    """Validate, canonicalize, and hash an incoming tool call into an ActionEnvelope."""
    try:
        clean_tool = canonicalize_unicode(tool).strip().lower()
        clean_verb = canonicalize_unicode(verb).strip().lower()
        clean_session = canonicalize_unicode(session_id).strip()
        clean_agent_id = canonicalize_unicode(agent_id).strip()
        clean_framework = canonicalize_unicode(framework).strip()
        clean_model = canonicalize_unicode(model).strip()
        clean_resource = canonicalize_resource(resource)
        clean_params = _canonicalize_params(params or {})
        clean_idem = (
            canonicalize_unicode(idempotency_key).strip()
            if idempotency_key is not None
            else None
        )
    except CanonicalizationError as exc:
        raise EnvelopeError(f"Canonicalization failed: {exc}") from exc

    if not clean_tool:
        raise EnvelopeError("tool must be non-empty")
    if clean_verb not in _VALID_VERBS:
        raise EnvelopeError(f"Invalid verb {clean_verb!r}; expected one of {sorted(_VALID_VERBS)}")
    if not clean_session:
        raise EnvelopeError("session_id must be non-empty")
    if not clean_agent_id:
        raise EnvelopeError("agent_id must be non-empty")
    if not isinstance(clean_params, dict):
        raise EnvelopeError("params must be a JSON object")

    intent_obj: IntentInfo | None = None
    if user_goal is not None:
        if declared_by not in _VALID_DECLARED_BY:
            raise EnvelopeError(f"Invalid declared_by: {declared_by!r}")
        intent_obj = IntentInfo(
            user_goal=canonicalize_unicode(user_goal, allow_newlines=True),
            declared_by=declared_by,
        )

    prov_tuple = tuple(provenance)
    for item in prov_tuple:
        if item.trust not in _VALID_TRUST:
            raise EnvelopeError(f"Invalid provenance trust: {item.trust!r}")

    action = ActionSpec(
        tool=clean_tool,
        verb=clean_verb,
        resource=clean_resource,
        params=clean_params,
        idempotency_key=clean_idem,
    )
    envelope_version = "1"
    canonical_hash = compute_action_hash(
        envelope_version=envelope_version,
        session_id=clean_session,
        agent_id=clean_agent_id,
        action=action,
    )

    return ActionEnvelope(
        envelope_version=envelope_version,
        crossing_id=crossing_id or generate_crossing_id(),
        session_id=clean_session,
        agent=AgentInfo(id=clean_agent_id, framework=clean_framework, model=clean_model),
        action=action,
        canonical_hash=canonical_hash,
        ts=ts or utc_now_iso(),
        intent=intent_obj,
        provenance=prov_tuple,
    )
