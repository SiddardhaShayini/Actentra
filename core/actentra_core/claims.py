"""Cryptographically bound execution claims for external outcome reporting (Finding 05).

A One-Time Execution Claim binds an allowed crossing to a specific authenticated
executor principal, session, and canonical hash. It prevents unauthorized outcome
fabrication, claim reuse, and cross-executor outcome spoofing.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Literal

from actentra_core.canonicalize import canonicalize_unicode, hash_canonical

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class ExecutionClaimError(ValueError):
    """Raised when an execution claim is missing, invalid, expired, or replayed."""


def generate_claim_id() -> str:
    """Generate a 26-character Crockford Base32 identifier with 'claim_' prefix."""
    ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand_bytes = os.urandom(10)
    value = (ts_ms << 80) | int.from_bytes(rand_bytes, "big")
    chars = ["0"] * 26
    for i in range(25, -1, -1):
        chars[i] = _CROCKFORD[value & 0x1F]
        value >>= 5
    return f"claim_{''.join(chars)}"


def compute_claim_hash(
    *,
    claim_id: str,
    crossing_id: str,
    executor_principal_id: str,
    session_id: str,
    canonical_hash: str,
    issued_at: str,
    expires_at: float,
    approval_or_warrant_id: str | None = None,
    result_digest: str | None = None,
    evidence_id: str | None = None,
    verification_status: str = "unverified",
    context_hash: str | None = None,
) -> str:
    """Compute deterministic SHA-256 canonical hash of execution claim metadata."""
    payload = {
        "claim_id": canonicalize_unicode(claim_id).strip(),
        "crossing_id": canonicalize_unicode(crossing_id).strip(),
        "executor_principal_id": canonicalize_unicode(executor_principal_id).strip(),
        "session_id": canonicalize_unicode(session_id).strip(),
        "canonical_hash": canonicalize_unicode(canonical_hash).strip(),
        "issued_at": canonicalize_unicode(issued_at).strip(),
        "expires_at": str(round(expires_at, 3)),
        "approval_or_warrant_id": (
            canonicalize_unicode(approval_or_warrant_id).strip()
            if approval_or_warrant_id is not None
            else None
        ),
        "result_digest": (
            canonicalize_unicode(result_digest).strip()
            if result_digest is not None
            else None
        ),
        "evidence_id": (
            canonicalize_unicode(evidence_id).strip()
            if evidence_id is not None
            else None
        ),
        "verification_status": canonicalize_unicode(verification_status).strip().lower(),
        "context_hash": (
            canonicalize_unicode(context_hash).strip()
            if context_hash is not None
            else None
        ),
    }
    return hash_canonical(payload)


@dataclass(frozen=True, slots=True)
class ExecutionClaim:
    """Durable record of a one-time execution claim for an external crossing."""

    claim_id: str
    crossing_id: str
    executor_principal_id: str
    session_id: str
    canonical_hash: str
    status: Literal["issued", "consumed", "expired"]
    issued_at: str
    expires_at: float
    consumed_at: str | None = None
    approval_or_warrant_id: str | None = None
    result_digest: str | None = None
    evidence_id: str | None = None
    verification_status: str = "unverified"
    context_hash: str | None = None
    claim_hash: str = ""

    def is_expired(self, now: float | None = None) -> bool:
        """Return True if the claim has exceeded its expiration timestamp."""
        check_time = now if now is not None else time.time()
        return check_time > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Convert claim to dictionary for API serialization."""
        return {
            "claim_id": self.claim_id,
            "crossing_id": self.crossing_id,
            "executor_principal_id": self.executor_principal_id,
            "session_id": self.session_id,
            "canonical_hash": self.canonical_hash,
            "status": self.status,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "consumed_at": self.consumed_at,
            "approval_or_warrant_id": self.approval_or_warrant_id,
            "result_digest": self.result_digest,
            "evidence_id": self.evidence_id,
            "verification_status": self.verification_status,
            "context_hash": self.context_hash,
            "claim_hash": self.claim_hash,
        }
