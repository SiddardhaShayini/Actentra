"""Observation contract and verifiable state records for Actentra (Phase 2)."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from actentra_core.canonicalize import (
    canonicalize_resource,
    canonicalize_unicode,
    hash_canonical,
)

_VALID_STATUSES: frozenset[str] = frozenset({"verified", "refuted", "unknown", "error", "stale"})
_VALID_TRUST_DOMAINS: frozenset[str] = frozenset(
    {"local_host", "remote_service", "external_witness"}
)
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class ObservationError(ValueError):
    """Raised when an Observation record fails construction or validation."""


def generate_observation_id() -> str:
    """Generate a Crockford Base32 identifier with 'obs_' prefix."""
    ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand_bytes = os.urandom(10)
    value = (ts_ms << 80) | int.from_bytes(rand_bytes, "big")
    chars = ["0"] * 26
    for i in range(25, -1, -1):
        chars[i] = _CROCKFORD[value & 0x1F]
        value >>= 5
    return f"obs_{''.join(chars)}"


def utc_iso(ts: float | None = None) -> str:
    """Format UTC timestamp in ISO-8601 format."""
    dt = datetime.fromtimestamp(ts, UTC) if ts is not None else datetime.now(UTC)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(iso_str: str) -> float:
    """Parse ISO-8601 string to unix timestamp in seconds."""
    clean = iso_str.replace("Z", "+00:00")
    return datetime.fromisoformat(clean).timestamp()


def compute_observation_hash(
    *,
    observation_id: str,
    observation_version: str,
    crossing_id: str | None,
    subject_resource: str,
    claim: str,
    status: str,
    observed_digest: str | None,
    observed_at: str,
    expires_at: str | None,
    verifier_id: str,
    verifier_version: str,
    trust_domain: str,
    metadata: dict[str, Any],
    error: str | None,
) -> str:
    """Compute the SHA-256 canonical hash of the observation payload."""
    payload = {
        "observation_id": observation_id,
        "observation_version": observation_version,
        "crossing_id": crossing_id,
        "subject_resource": subject_resource,
        "claim": claim,
        "status": status,
        "observed_digest": observed_digest,
        "observed_at": observed_at,
        "expires_at": expires_at,
        "verifier_id": verifier_id,
        "verifier_version": verifier_version,
        "trust_domain": trust_domain,
        "metadata": metadata,
        "error": error,
    }
    return hash_canonical(payload)


@dataclass(frozen=True, slots=True)
class ObservationRecord:
    """Durable record of a scoped state observation."""

    observation_id: str
    observation_version: str
    crossing_id: str | None
    subject_resource: str
    claim: str
    status: Literal["verified", "refuted", "unknown", "error", "stale"]
    observed_digest: str | None
    observed_at: str
    expires_at: str | None
    verifier_id: str
    verifier_version: str
    trust_domain: Literal["local_host", "remote_service", "external_witness"]
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    observation_hash: str = ""

    def is_fresh(self, now: float | None = None) -> bool:
        """Return True if the observation has not elapsed past its expires_at timestamp."""
        if self.expires_at is None:
            return True
        check_time = now if now is not None else time.time()
        try:
            return check_time < parse_iso(self.expires_at)
        except Exception:
            return False

    def verify_integrity(self) -> bool:
        """Verify that observation_hash strictly matches computed canonical payload hash."""
        expected = compute_observation_hash(
            observation_id=self.observation_id,
            observation_version=self.observation_version,
            crossing_id=self.crossing_id,
            subject_resource=self.subject_resource,
            claim=self.claim,
            status=self.status,
            observed_digest=self.observed_digest,
            observed_at=self.observed_at,
            expires_at=self.expires_at,
            verifier_id=self.verifier_id,
            verifier_version=self.verifier_version,
            trust_domain=self.trust_domain,
            metadata=self.metadata,
            error=self.error,
        )
        return self.observation_hash == expected

    def to_dict(self) -> dict[str, Any]:
        """Convert record to dictionary for API serialization."""
        return {
            "observation_id": self.observation_id,
            "observation_version": self.observation_version,
            "crossing_id": self.crossing_id,
            "subject_resource": self.subject_resource,
            "claim": self.claim,
            "status": self.status,
            "observed_digest": self.observed_digest,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "verifier_id": self.verifier_id,
            "verifier_version": self.verifier_version,
            "trust_domain": self.trust_domain,
            "metadata": dict(self.metadata),
            "error": self.error,
            "observation_hash": self.observation_hash,
            "fresh": self.is_fresh(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ObservationRecord:
        """Construct ObservationRecord from dictionary representation."""
        return cls(
            observation_id=str(data["observation_id"]),
            observation_version=str(data.get("observation_version", "1")),
            crossing_id=str(data["crossing_id"]) if data.get("crossing_id") else None,
            subject_resource=str(data["subject_resource"]),
            claim=str(data["claim"]),
            status=data["status"],
            observed_digest=(str(data["observed_digest"]) if data.get("observed_digest") else None),
            observed_at=str(data["observed_at"]),
            expires_at=str(data["expires_at"]) if data.get("expires_at") else None,
            verifier_id=str(data["verifier_id"]),
            verifier_version=str(data["verifier_version"]),
            trust_domain=data["trust_domain"],
            metadata=dict(data.get("metadata") or {}),
            error=str(data["error"]) if data.get("error") else None,
            observation_hash=str(data.get("observation_hash", "")),
        )


def build_observation(
    *,
    subject_resource: str,
    claim: str,
    status: Literal["verified", "refuted", "unknown", "error", "stale"],
    verifier_id: str,
    verifier_version: str = "1.0.0",
    trust_domain: Literal["local_host", "remote_service", "external_witness"] = "local_host",
    observed_digest: str | None = None,
    crossing_id: str | None = None,
    expires_at: str | None = None,
    metadata: dict[str, Any] | None = None,
    error: str | None = None,
    observation_id: str | None = None,
    observed_at: str | None = None,
) -> ObservationRecord:
    """Validate, canonicalize, hash, and construct an ObservationRecord."""
    try:
        clean_res = canonicalize_resource(subject_resource)
    except Exception:
        clean_res = canonicalize_unicode(subject_resource).strip()
    clean_claim = canonicalize_unicode(claim).strip().lower()
    clean_status = status.strip().lower()
    if clean_status not in _VALID_STATUSES:
        raise ObservationError(
            f"Invalid status {clean_status!r}; expected one of {sorted(_VALID_STATUSES)}"
        )
    if trust_domain not in _VALID_TRUST_DOMAINS:
        raise ObservationError(
            f"Invalid trust_domain {trust_domain!r}; expected one of {sorted(_VALID_TRUST_DOMAINS)}"
        )

    obs_id = observation_id or generate_observation_id()
    obs_version = "1"
    obs_time = observed_at or utc_iso()
    clean_meta = dict(metadata or {})

    obs_hash = compute_observation_hash(
        observation_id=obs_id,
        observation_version=obs_version,
        crossing_id=crossing_id,
        subject_resource=clean_res,
        claim=clean_claim,
        status=clean_status,
        observed_digest=observed_digest,
        observed_at=obs_time,
        expires_at=expires_at,
        verifier_id=verifier_id,
        verifier_version=verifier_version,
        trust_domain=trust_domain,
        metadata=clean_meta,
        error=error,
    )

    return ObservationRecord(
        observation_id=obs_id,
        observation_version=obs_version,
        crossing_id=crossing_id,
        subject_resource=clean_res,
        claim=clean_claim,
        status=clean_status,  # type: ignore[arg-type]
        observed_digest=observed_digest,
        observed_at=obs_time,
        expires_at=expires_at,
        verifier_id=verifier_id,
        verifier_version=verifier_version,
        trust_domain=trust_domain,
        metadata=clean_meta,
        error=error,
        observation_hash=obs_hash,
    )
