"""Task Handoff and Cross-Agent Continuity for Actentra (Phase 4).

Provides durable, tamper-evident cross-agent handoff records that bind initiator,
assigned executor, and independent verifier agent identities, enforce scoped
authorizations, and link prior crossings and verifiable state observations.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from actentra_core.canonicalize import hash_canonical, match_resource_pattern

_VALID_STATUSES: frozenset[str] = frozenset(
    {"active", "completed", "revoked", "expired", "contradicted"}
)
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class HandoffError(ValueError):
    """Raised when a task handoff operation fails."""


class UnauthorizedAgentHandoffError(HandoffError):
    """Raised when an agent attempts to access or advance a handoff assigned to another agent."""


class ExpiredHandoffError(HandoffError):
    """Raised when an operation is attempted against an expired handoff."""


class ContradictionDetectedError(HandoffError):
    """Raised when an independent verifier observes a state contradiction."""


def generate_handoff_id() -> str:
    """Generate a Crockford Base32 identifier with 'hnd_' prefix."""
    ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand_bytes = os.urandom(10)
    value = (ts_ms << 80) | int.from_bytes(rand_bytes, "big")
    chars = ["0"] * 26
    for i in range(25, -1, -1):
        chars[i] = _CROCKFORD[value & 0x1F]
        value >>= 5
    return f"hnd_{''.join(chars)}"


def utc_iso(ts: float | None = None) -> str:
    """Format UTC timestamp in ISO-8601 format."""
    dt = datetime.fromtimestamp(ts, UTC) if ts is not None else datetime.now(UTC)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(iso_str: str) -> float:
    """Parse ISO-8601 string to unix timestamp in seconds."""
    clean = iso_str.replace("Z", "+00:00")
    return datetime.fromisoformat(clean).timestamp()


def compute_handoff_hash(
    *,
    handoff_id: str,
    handoff_version: str,
    task_id: str,
    status: str,
    current_step: int,
    initiator_agent_id: str,
    assigned_agent_id: str,
    verifier_agent_id: str,
    allowed_verbs: list[str] | tuple[str, ...],
    allowed_resources: list[str] | tuple[str, ...],
    prior_crossings: list[str] | tuple[str, ...],
    prior_observations: list[str] | tuple[str, ...],
    assertions: dict[str, Any],
    contradictions: list[str] | tuple[str, ...],
    created_at: str,
    expires_at: str | None,
) -> str:
    """Compute the SHA-256 canonical hash of the task handoff payload."""
    payload = {
        "handoff_id": handoff_id,
        "handoff_version": handoff_version,
        "task_id": task_id,
        "status": status,
        "current_step": current_step,
        "initiator_agent_id": initiator_agent_id,
        "assigned_agent_id": assigned_agent_id,
        "verifier_agent_id": verifier_agent_id,
        "allowed_verbs": list(allowed_verbs),
        "allowed_resources": list(allowed_resources),
        "prior_crossings": list(prior_crossings),
        "prior_observations": list(prior_observations),
        "assertions": assertions,
        "contradictions": list(contradictions),
        "created_at": created_at,
        "expires_at": expires_at,
    }
    return hash_canonical(payload)


@dataclass(frozen=True, slots=True)
class TaskHandoffRecord:
    """Durable record of a cross-agent task handoff."""

    handoff_id: str
    handoff_version: str
    task_id: str
    status: Literal["active", "completed", "revoked", "expired", "contradicted"]
    current_step: int
    initiator_agent_id: str
    assigned_agent_id: str
    verifier_agent_id: str
    allowed_verbs: tuple[str, ...]
    allowed_resources: tuple[str, ...]
    prior_crossings: tuple[str, ...]
    prior_observations: tuple[str, ...]
    assertions: dict[str, Any] = field(default_factory=dict)
    contradictions: tuple[str, ...] = field(default_factory=tuple)
    created_at: str = ""
    expires_at: str | None = None
    handoff_hash: str = ""

    def is_fresh(self, now: float | None = None) -> bool:
        """Return True if handoff has not expired."""
        if self.expires_at is None:
            return True
        check_time = now if now is not None else time.time()
        try:
            return check_time < parse_iso(self.expires_at)
        except Exception:
            return False

    def verify_integrity(self) -> bool:
        """Verify handoff_hash matches computed canonical payload hash."""
        expected = compute_handoff_hash(
            handoff_id=self.handoff_id,
            handoff_version=self.handoff_version,
            task_id=self.task_id,
            status=self.status,
            current_step=self.current_step,
            initiator_agent_id=self.initiator_agent_id,
            assigned_agent_id=self.assigned_agent_id,
            verifier_agent_id=self.verifier_agent_id,
            allowed_verbs=self.allowed_verbs,
            allowed_resources=self.allowed_resources,
            prior_crossings=self.prior_crossings,
            prior_observations=self.prior_observations,
            assertions=self.assertions,
            contradictions=self.contradictions,
            created_at=self.created_at,
            expires_at=self.expires_at,
        )
        return self.handoff_hash == expected

    def validate_caller(self, caller_agent_id: str) -> None:
        """Verify that caller_agent_id matches assigned_agent_id and handoff is active."""
        if not self.is_fresh():
            raise ExpiredHandoffError(
                f"Handoff '{self.handoff_id}' for task '{self.task_id}' has expired"
            )
        if self.status != "active":
            raise HandoffError(
                f"Handoff '{self.handoff_id}' is not active (status='{self.status}')"
            )
        if caller_agent_id != self.assigned_agent_id:
            raise UnauthorizedAgentHandoffError(
                f"Agent '{caller_agent_id}' is not authorized for handoff '{self.handoff_id}'. "
                f"Assigned agent is '{self.assigned_agent_id}'"
            )

    def is_action_permitted(self, verb: str, resource: str) -> bool:
        """Check whether verb and resource conform to the handoff scope."""
        if self.allowed_verbs and verb.lower() not in [v.lower() for v in self.allowed_verbs]:
            return False
        if self.allowed_resources:
            matched = any(
                match_resource_pattern(pat, resource) for pat in self.allowed_resources
            )
            if not matched:
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        """Convert record to dictionary for JSON serialization."""
        return {
            "handoff_id": self.handoff_id,
            "handoff_version": self.handoff_version,
            "task_id": self.task_id,
            "status": self.status,
            "current_step": self.current_step,
            "initiator_agent_id": self.initiator_agent_id,
            "assigned_agent_id": self.assigned_agent_id,
            "verifier_agent_id": self.verifier_agent_id,
            "allowed_verbs": list(self.allowed_verbs),
            "allowed_resources": list(self.allowed_resources),
            "prior_crossings": list(self.prior_crossings),
            "prior_observations": list(self.prior_observations),
            "assertions": dict(self.assertions),
            "contradictions": list(self.contradictions),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "handoff_hash": self.handoff_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TaskHandoffRecord:
        """Reconstruct record from dictionary representation."""
        return cls(
            handoff_id=str(data["handoff_id"]),
            handoff_version=str(data.get("handoff_version", "1")),
            task_id=str(data["task_id"]),
            status=data["status"],
            current_step=int(data.get("current_step", 1)),
            initiator_agent_id=str(data["initiator_agent_id"]),
            assigned_agent_id=str(data["assigned_agent_id"]),
            verifier_agent_id=str(data["verifier_agent_id"]),
            allowed_verbs=tuple(data.get("allowed_verbs") or ()),
            allowed_resources=tuple(data.get("allowed_resources") or ()),
            prior_crossings=tuple(data.get("prior_crossings") or ()),
            prior_observations=tuple(data.get("prior_observations") or ()),
            assertions=dict(data.get("assertions") or {}),
            contradictions=tuple(data.get("contradictions") or ()),
            created_at=str(data.get("created_at") or utc_iso()),
            expires_at=data.get("expires_at"),
            handoff_hash=str(data.get("handoff_hash", "")),
        )


def build_handoff(
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
    contradictions: list[str] | tuple[str, ...] = (),
    current_step: int = 1,
    status: Literal["active", "completed", "revoked", "expired", "contradicted"] = "active",
    ttl_seconds: float | None = 3600.0,
    handoff_id: str | None = None,
    created_at: str | None = None,
) -> TaskHandoffRecord:
    """Build and hash a TaskHandoffRecord."""
    if status not in _VALID_STATUSES:
        raise HandoffError(f"Invalid handoff status: {status!r}")

    hid = handoff_id or generate_handoff_id()
    now_ts = time.time()
    ts_created = created_at or utc_iso(now_ts)
    ts_expires = utc_iso(now_ts + ttl_seconds) if ttl_seconds is not None else None

    clean_verbs = tuple(str(v).strip().lower() for v in allowed_verbs if v)
    clean_resources = tuple(str(r).strip() for r in allowed_resources if r)
    clean_crossings = tuple(str(c).strip() for c in prior_crossings if c)
    clean_observations = tuple(str(o).strip() for o in prior_observations if o)
    clean_assertions = dict(assertions or {})
    clean_contradictions = tuple(str(c).strip() for c in contradictions if c)

    h_hash = compute_handoff_hash(
        handoff_id=hid,
        handoff_version="1",
        task_id=task_id,
        status=status,
        current_step=current_step,
        initiator_agent_id=initiator_agent_id,
        assigned_agent_id=assigned_agent_id,
        verifier_agent_id=verifier_agent_id,
        allowed_verbs=clean_verbs,
        allowed_resources=clean_resources,
        prior_crossings=clean_crossings,
        prior_observations=clean_observations,
        assertions=clean_assertions,
        contradictions=clean_contradictions,
        created_at=ts_created,
        expires_at=ts_expires,
    )

    return TaskHandoffRecord(
        handoff_id=hid,
        handoff_version="1",
        task_id=task_id,
        status=status,
        current_step=current_step,
        initiator_agent_id=initiator_agent_id,
        assigned_agent_id=assigned_agent_id,
        verifier_agent_id=verifier_agent_id,
        allowed_verbs=clean_verbs,
        allowed_resources=clean_resources,
        prior_crossings=clean_crossings,
        prior_observations=clean_observations,
        assertions=clean_assertions,
        contradictions=clean_contradictions,
        created_at=ts_created,
        expires_at=ts_expires,
        handoff_hash=h_hash,
    )
