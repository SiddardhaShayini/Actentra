"""Action execution lifecycle state machine and durable idempotency models.

Phase 7: Production Reliability Engineering (Invariant I16).
Provides deterministic, verifiable state transitions for actions and enforces
at-most-once execution of side effects via durable idempotency keys.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Literal

ActionLifecycleState = Literal[
    "created",
    "authorized",
    "approved",
    "claimed",
    "executing",
    "verification_pending",
    "succeeded",
    "failed",
    "unknown",
    "reconciliation_required",
]

VALID_LIFECYCLE_STATES: frozenset[str] = frozenset(
    {
        "created",
        "authorized",
        "approved",
        "claimed",
        "executing",
        "verification_pending",
        "succeeded",
        "failed",
        "unknown",
        "reconciliation_required",
    }
)

# Explicit, transactional lifecycle state transition map.
# Any transition not listed here is illegal and will raise InvalidStateTransitionError.
LEGAL_TRANSITIONS: dict[str, frozenset[str]] = {
    "created": frozenset({"authorized", "failed"}),
    "authorized": frozenset({"approved", "claimed", "failed"}),
    "approved": frozenset({"claimed", "failed"}),
    "claimed": frozenset({"executing", "failed"}),
    "executing": frozenset(
        {
            "verification_pending",
            "succeeded",
            "failed",
            "unknown",
            "reconciliation_required",
        }
    ),
    "verification_pending": frozenset(
        {
            "succeeded",
            "failed",
            "unknown",
            "reconciliation_required",
        }
    ),
    "unknown": frozenset(
        {
            "reconciliation_required",
            "succeeded",
            "failed",
        }
    ),
    "reconciliation_required": frozenset(
        {
            "succeeded",
            "failed",
            "unknown",
        }
    ),
    "succeeded": frozenset(),  # Terminal state
    "failed": frozenset(),  # Terminal state
}

IdempotencyStatus = Literal["in_flight", "completed", "failed", "reconciliation_required"]
VALID_IDEMPOTENCY_STATUSES: frozenset[str] = frozenset(
    {
        "in_flight",
        "completed",
        "failed",
        "reconciliation_required",
    }
)


class LifecycleError(RuntimeError):
    """Base error for execution lifecycle state machine failures."""


class InvalidStateTransitionError(LifecycleError):
    """Raised when an illegal or ambiguous state transition is attempted."""

    def __init__(self, from_state: str, to_state: str, crossing_id: str) -> None:
        self.from_state = from_state
        self.to_state = to_state
        self.crossing_id = crossing_id
        super().__init__(
            f"Invalid action lifecycle transition from '{from_state}' to '{to_state}' "
            f"for crossing '{crossing_id}'"
        )


class IdempotencyError(RuntimeError):
    """Base error for durable idempotency violations."""


class IdempotencyConflictError(IdempotencyError):
    """Raised when an idempotency key is reused for a differing action payload."""

    def __init__(self, key: str, principal_id: str, message: str) -> None:
        self.key = key
        self.principal_id = principal_id
        super().__init__(
            f"Idempotency conflict for key '{key}' and principal '{principal_id}': {message}"
        )


class IdempotencyInFlightError(IdempotencyError):
    """Raised when an action with the given idempotency key is currently executing."""

    def __init__(self, key: str, principal_id: str, crossing_id: str) -> None:
        self.key = key
        self.principal_id = principal_id
        self.crossing_id = crossing_id
        super().__init__(
            f"Action with idempotency key '{key}' is currently in-flight (crossing '{crossing_id}')"
        )


class ReconciliationRequiredError(IdempotencyError):
    """Raised when an action previously ended in an uncertain state and requires reconciliation."""

    def __init__(self, key: str, principal_id: str, crossing_id: str) -> None:
        self.key = key
        self.principal_id = principal_id
        self.crossing_id = crossing_id
        super().__init__(
            f"Action with idempotency key '{key}' ended in uncertain state "
            f"(crossing '{crossing_id}'); reconciliation is required before replay"
        )


class DatabaseUnavailableError(RuntimeError):
    """Raised when persistent storage fails or enters an unrecoverable state (fail-closed)."""


def validate_lifecycle_transition(
    from_state: str,
    to_state: str,
    *,
    crossing_id: str = "unknown",
) -> None:
    """Validate whether transitioning from from_state to to_state is legal.

    Raises:
        InvalidStateTransitionError: if the transition is disallowed.
    """
    if from_state not in LEGAL_TRANSITIONS:
        raise InvalidStateTransitionError(from_state, to_state, crossing_id)
    allowed = LEGAL_TRANSITIONS[from_state]
    if to_state not in allowed:
        raise InvalidStateTransitionError(from_state, to_state, crossing_id)


@dataclass(frozen=True, slots=True)
class ActionLifecycleRecord:
    """Durable record of an action's current lifecycle state."""

    crossing_id: str
    current_state: ActionLifecycleState
    session_id: str
    principal_id: str
    canonical_hash: str
    idempotency_key: str | None
    created_at: str
    updated_at: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "crossing_id": self.crossing_id,
            "current_state": self.current_state,
            "session_id": self.session_id,
            "principal_id": self.principal_id,
            "canonical_hash": self.canonical_hash,
            "idempotency_key": self.idempotency_key,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class ActionTransitionRecord:
    """Immutable audit trail entry for a state transition."""

    transition_id: str
    crossing_id: str
    from_state: str
    to_state: str
    transitioned_at: str
    actor_id: str
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "transition_id": self.transition_id,
            "crossing_id": self.crossing_id,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "transitioned_at": self.transitioned_at,
            "actor_id": self.actor_id,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class IdempotencyRecord:
    """Durable record tracking an idempotency key to prevent replay side effects."""

    idempotency_key: str
    principal_id: str
    canonical_hash: str
    tool: str
    verb: str
    crossing_id: str
    status: IdempotencyStatus
    created_at: str
    expires_at: float
    result_hash: str | None = None
    response: dict[str, Any] | None = None

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "idempotency_key": self.idempotency_key,
            "principal_id": self.principal_id,
            "canonical_hash": self.canonical_hash,
            "tool": self.tool,
            "verb": self.verb,
            "crossing_id": self.crossing_id,
            "status": self.status,
            "result_hash": self.result_hash,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "expires_in_seconds": max(0.0, round(self.expires_at - time.time(), 1)),
            "response": dict(self.response) if self.response is not None else None,
        }
