"""Evidence quality taxonomy, provenance, and freshness model for Actentra (V5).

Provides a formal representation of execution evidence distinguishing:
- locally_observed: directly executed by Actentra's registered scoped executors
- caller_reported: reported by external callers without local verification
- externally_verified: verified against independent ground truth by a verifier
- stale: expired observation whose freshness guarantee has lapsed
- unknown: unconfirmed in-flight execution or crash recovery
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from actentra_core.canonicalize import canonicalize_json, canonicalize_unicode, hash_canonical
from actentra_core.envelope import generate_crossing_id, utc_now_iso


class EvidenceTier(StrEnum):
    """First-class evidence quality tiers."""

    LOCALLY_OBSERVED = "locally_observed"
    CALLER_REPORTED = "caller_reported"
    EXTERNALLY_VERIFIED = "externally_verified"
    STALE = "stale"
    UNKNOWN = "unknown"


_VALID_TIERS = frozenset(e.value for e in EvidenceTier)


class EvidenceError(ValueError):
    """Raised when an evidence record cannot be constructed or validated."""


def compute_evidence_hash(
    *,
    evidence_id: str,
    crossing_id: str,
    tier: str,
    trust_domain: str,
    collector: str,
    observed_at: str,
    expires_at: str | None,
    details: dict[str, Any],
) -> str:
    """Compute deterministic SHA-256 hash over canonical evidence record payload."""
    payload = {
        "evidence_id": evidence_id,
        "crossing_id": crossing_id,
        "tier": tier,
        "trust_domain": trust_domain,
        "collector": collector,
        "observed_at": observed_at,
        "expires_at": expires_at,
        "details": details,
    }
    return hash_canonical(payload)


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """Immutable evidence record with provenance, freshness, and quality tier."""

    evidence_id: str
    crossing_id: str
    tier: EvidenceTier
    trust_domain: str
    collector: str
    observed_at: str
    expires_at: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    evidence_hash: str = ""

    def is_fresh(self, as_of: str | datetime | None = None) -> bool:
        """Return True if record has not expired."""
        if self.expires_at is None:
            return True
        if as_of is None:
            now_dt = datetime.now(UTC)
        elif isinstance(as_of, str):
            clean_ts = as_of.replace("Z", "+00:00")
            now_dt = datetime.fromisoformat(clean_ts)
            if now_dt.tzinfo is None:
                now_dt = now_dt.replace(tzinfo=UTC)
        else:
            now_dt = as_of
            if now_dt.tzinfo is None:
                now_dt = now_dt.replace(tzinfo=UTC)

        clean_exp = self.expires_at.replace("Z", "+00:00")
        exp_dt = datetime.fromisoformat(clean_exp)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=UTC)

        return now_dt < exp_dt

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable dictionary representation."""
        return {
            "evidence_id": self.evidence_id,
            "crossing_id": self.crossing_id,
            "tier": self.tier.value,
            "trust_domain": self.trust_domain,
            "collector": self.collector,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "details": self.details,
            "evidence_hash": self.evidence_hash,
        }


def build_evidence_record(
    *,
    crossing_id: str,
    tier: str | EvidenceTier,
    trust_domain: str,
    collector: str,
    details: dict[str, Any] | None = None,
    evidence_id: str | None = None,
    observed_at: str | None = None,
    expires_at: str | None = None,
) -> EvidenceRecord:
    """Validate, canonicalize, and construct a hashed EvidenceRecord."""
    raw_tier = tier.value if isinstance(tier, EvidenceTier) else str(tier).lower().strip()
    if raw_tier not in _VALID_TIERS:
        raise EvidenceError(
            f"Invalid evidence tier {raw_tier!r}; expected one of {sorted(_VALID_TIERS)}"
        )

    clean_cid = canonicalize_unicode(crossing_id).strip()
    if not clean_cid:
        raise EvidenceError("crossing_id must be non-empty")

    clean_domain = canonicalize_unicode(trust_domain).strip()
    if not clean_domain:
        raise EvidenceError("trust_domain must be non-empty")

    clean_collector = canonicalize_unicode(collector).strip()
    if not clean_collector:
        raise EvidenceError("collector must be non-empty")

    eid = evidence_id.strip() if evidence_id else generate_crossing_id()
    obs_time = observed_at or utc_now_iso()

    clean_details = details if details is not None else {}
    if not isinstance(clean_details, dict):
        raise EvidenceError("details must be a dictionary")

    # Ensure details can be canonicalized
    try:
        canonicalize_json(clean_details)
    except Exception as exc:
        raise EvidenceError(f"details dictionary is not JSON-serializable: {exc}") from exc

    ev_hash = compute_evidence_hash(
        evidence_id=eid,
        crossing_id=clean_cid,
        tier=raw_tier,
        trust_domain=clean_domain,
        collector=clean_collector,
        observed_at=obs_time,
        expires_at=expires_at,
        details=clean_details,
    )

    return EvidenceRecord(
        evidence_id=eid,
        crossing_id=clean_cid,
        tier=EvidenceTier(raw_tier),
        trust_domain=clean_domain,
        collector=clean_collector,
        observed_at=obs_time,
        expires_at=expires_at,
        details=clean_details,
        evidence_hash=ev_hash,
    )
