"""Observation contract and verifiable state records for Actentra (Phase 2)."""

from __future__ import annotations

import hmac
import math
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
_GENERIC_FORBIDDEN_CLAIMS: frozenset[str] = frozenset(
    {"verified", "ok", "success", "true", "any", "all", "none", "pass", "valid", ""}
)
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class ObservationError(ValueError):
    """Raised when an Observation record fails construction or validation."""


def _generate_crockford_id(prefix: str) -> str:
    ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand_bytes = os.urandom(10)
    value = (ts_ms << 80) | int.from_bytes(rand_bytes, "big")
    chars = ["0"] * 26
    for i in range(25, -1, -1):
        chars[i] = _CROCKFORD[value & 0x1F]
        value >>= 5
    return f"{prefix}{''.join(chars)}"


def generate_observation_id() -> str:
    """Generate a Crockford Base32 identifier with 'obs_' prefix."""
    return _generate_crockford_id("obs_")


def generate_verification_id() -> str:
    """Generate a Crockford Base32 identifier with 'ver_' prefix."""
    return _generate_crockford_id("ver_")


def utc_iso(ts: float | None = None) -> str:
    """Format UTC timestamp in ISO-8601 format."""
    dt = datetime.fromtimestamp(ts, UTC) if ts is not None else datetime.now(UTC)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(iso_str: str) -> float:
    """Parse ISO-8601 string to unix timestamp in seconds."""
    clean = iso_str.replace("Z", "+00:00")
    return datetime.fromisoformat(clean).timestamp()


def compute_verification_context_hash(
    *,
    verification_id: str,
    crossing_id: str,
    canonical_action_hash: str,
    authorized_resource: str,
    expected_postcondition: str,
    expected_digest: str | None,
    claim_id: str,
    executor_principal_id: str,
    verifier_principal_id: str,
    policy_version: str,
    observed_at: str,
    expires_at: str,
) -> str:
    """Compute canonical SHA-256 hash binding an immutable VerificationContext."""
    payload = {
        "verification_id": canonicalize_unicode(verification_id).strip(),
        "crossing_id": canonicalize_unicode(crossing_id).strip(),
        "canonical_action_hash": canonicalize_unicode(canonical_action_hash).strip(),
        "authorized_resource": canonicalize_unicode(authorized_resource).strip(),
        "expected_postcondition": canonicalize_unicode(expected_postcondition).strip().lower(),
        "expected_digest": (
            canonicalize_unicode(expected_digest).strip().lower()
            if expected_digest is not None
            else None
        ),
        "claim_id": canonicalize_unicode(claim_id).strip(),
        "executor_principal_id": canonicalize_unicode(executor_principal_id).strip(),
        "verifier_principal_id": canonicalize_unicode(verifier_principal_id).strip(),
        "policy_version": canonicalize_unicode(policy_version).strip(),
        "observed_at": canonicalize_unicode(observed_at).strip(),
        "expires_at": canonicalize_unicode(expires_at).strip(),
    }
    return hash_canonical(payload)


@dataclass(frozen=True, slots=True)
class VerificationContext:
    """Immutable, cryptographically bound verification context for external observations."""

    verification_id: str
    crossing_id: str
    canonical_action_hash: str
    authorized_resource: str
    expected_postcondition: str
    expected_digest: str | None
    claim_id: str
    executor_principal_id: str
    verifier_principal_id: str
    policy_version: str
    observed_at: str
    expires_at: str
    context_hash: str = ""

    def is_fresh(self, now: float | None = None) -> bool:
        """Return True if current time is strictly before expires_at."""
        check_time = now if now is not None else time.time()
        try:
            return check_time < parse_iso(self.expires_at)
        except Exception:
            return False

    def verify_integrity(self) -> bool:
        """Verify context_hash matches canonical serialization of all bound fields."""
        expected = compute_verification_context_hash(
            verification_id=self.verification_id,
            crossing_id=self.crossing_id,
            canonical_action_hash=self.canonical_action_hash,
            authorized_resource=self.authorized_resource,
            expected_postcondition=self.expected_postcondition,
            expected_digest=self.expected_digest,
            claim_id=self.claim_id,
            executor_principal_id=self.executor_principal_id,
            verifier_principal_id=self.verifier_principal_id,
            policy_version=self.policy_version,
            observed_at=self.observed_at,
            expires_at=self.expires_at,
        )
        return hmac.compare_digest(self.context_hash, expected)

    def to_dict(self) -> dict[str, Any]:
        """Serialize VerificationContext to dictionary."""
        return {
            "verification_id": self.verification_id,
            "crossing_id": self.crossing_id,
            "canonical_action_hash": self.canonical_action_hash,
            "authorized_resource": self.authorized_resource,
            "expected_postcondition": self.expected_postcondition,
            "expected_digest": self.expected_digest,
            "claim_id": self.claim_id,
            "executor_principal_id": self.executor_principal_id,
            "verifier_principal_id": self.verifier_principal_id,
            "policy_version": self.policy_version,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "context_hash": self.context_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerificationContext:
        """Construct VerificationContext from dictionary."""
        return cls(
            verification_id=str(data["verification_id"]),
            crossing_id=str(data["crossing_id"]),
            canonical_action_hash=str(data["canonical_action_hash"]),
            authorized_resource=str(data["authorized_resource"]),
            expected_postcondition=str(data["expected_postcondition"]),
            expected_digest=(
                str(data["expected_digest"]) if data.get("expected_digest") is not None else None
            ),
            claim_id=str(data["claim_id"]),
            executor_principal_id=str(data["executor_principal_id"]),
            verifier_principal_id=str(data["verifier_principal_id"]),
            policy_version=str(data["policy_version"]),
            observed_at=str(data["observed_at"]),
            expires_at=str(data["expires_at"]),
            context_hash=str(data.get("context_hash", "")),
        )


def build_verification_context(
    *,
    crossing_id: str,
    canonical_action_hash: str,
    authorized_resource: str,
    expected_postcondition: str,
    claim_id: str,
    executor_principal_id: str,
    verifier_principal_id: str,
    policy_version: str,
    expected_digest: str | None = None,
    ttl_seconds: float = 60.0,
    now: float | None = None,
    verification_id: str | None = None,
) -> VerificationContext:
    """Validate, canonicalize, and cryptographically bind a VerificationContext."""
    if not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
        raise ObservationError(f"ttl_seconds must be positive and finite, got {ttl_seconds!r}")

    for label, val in (
        ("crossing_id", crossing_id),
        ("canonical_action_hash", canonical_action_hash),
        ("authorized_resource", authorized_resource),
        ("expected_postcondition", expected_postcondition),
        ("claim_id", claim_id),
        ("executor_principal_id", executor_principal_id),
        ("verifier_principal_id", verifier_principal_id),
        ("policy_version", policy_version),
    ):
        if not isinstance(val, str) or not val.strip():
            raise ObservationError(f"VerificationContext requires non-empty '{label}'")

    clean_post = canonicalize_unicode(expected_postcondition).strip().lower()
    if clean_post in _GENERIC_FORBIDDEN_CLAIMS:
        raise ObservationError(
            f"Generic postcondition claim {clean_post!r} is not permitted in VerificationContext"
        )

    try:
        clean_res = canonicalize_resource(authorized_resource)
    except Exception:
        clean_res = canonicalize_unicode(authorized_resource).strip()

    clean_digest = (
        canonicalize_unicode(expected_digest).strip().lower()
        if expected_digest is not None
        else None
    )
    if clean_post == "digest_match" and not clean_digest:
        raise ObservationError("expected_digest is required for 'digest_match' VerificationContext")

    curr = now if now is not None else time.time()
    obs_at = utc_iso(curr)
    exp_at = utc_iso(curr + ttl_seconds)
    ver_id = (
        canonicalize_unicode(verification_id).strip()
        if verification_id
        else generate_verification_id()
    )

    ctx_hash = compute_verification_context_hash(
        verification_id=ver_id,
        crossing_id=crossing_id.strip(),
        canonical_action_hash=canonical_action_hash.strip(),
        authorized_resource=clean_res,
        expected_postcondition=clean_post,
        expected_digest=clean_digest,
        claim_id=claim_id.strip(),
        executor_principal_id=executor_principal_id.strip(),
        verifier_principal_id=verifier_principal_id.strip(),
        policy_version=policy_version.strip(),
        observed_at=obs_at,
        expires_at=exp_at,
    )

    return VerificationContext(
        verification_id=ver_id,
        crossing_id=crossing_id.strip(),
        canonical_action_hash=canonical_action_hash.strip(),
        authorized_resource=clean_res,
        expected_postcondition=clean_post,
        expected_digest=clean_digest,
        claim_id=claim_id.strip(),
        executor_principal_id=executor_principal_id.strip(),
        verifier_principal_id=verifier_principal_id.strip(),
        policy_version=policy_version.strip(),
        observed_at=obs_at,
        expires_at=exp_at,
        context_hash=ctx_hash,
    )


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
    verification_id: str | None = None,
    claim_id: str | None = None,
    canonical_action_hash: str | None = None,
    expected_postcondition: str | None = None,
    expected_digest: str | None = None,
    executor_principal_id: str | None = None,
    verifier_principal_id: str | None = None,
    policy_version: str | None = None,
    verification_context_hash: str | None = None,
) -> str:
    """Compute the SHA-256 canonical hash of the observation payload."""
    payload: dict[str, Any] = {
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
    if any(
        val is not None
        for val in (
            verification_id,
            claim_id,
            canonical_action_hash,
            expected_postcondition,
            expected_digest,
            executor_principal_id,
            verifier_principal_id,
            policy_version,
            verification_context_hash,
        )
    ):
        payload.update(
            {
                "verification_id": verification_id,
                "claim_id": claim_id,
                "canonical_action_hash": canonical_action_hash,
                "expected_postcondition": expected_postcondition,
                "expected_digest": expected_digest,
                "executor_principal_id": executor_principal_id,
                "verifier_principal_id": verifier_principal_id,
                "policy_version": policy_version,
                "verification_context_hash": verification_context_hash,
            }
        )
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
    verification_id: str | None = None
    claim_id: str | None = None
    canonical_action_hash: str | None = None
    expected_postcondition: str | None = None
    expected_digest: str | None = None
    executor_principal_id: str | None = None
    verifier_principal_id: str | None = None
    policy_version: str | None = None
    verification_context_hash: str | None = None
    consumed_at: str | None = None
    consumed_by_crossing_id: str | None = None
    consumed_by_claim_id: str | None = None

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
            verification_id=self.verification_id,
            claim_id=self.claim_id,
            canonical_action_hash=self.canonical_action_hash,
            expected_postcondition=self.expected_postcondition,
            expected_digest=self.expected_digest,
            executor_principal_id=self.executor_principal_id,
            verifier_principal_id=self.verifier_principal_id,
            policy_version=self.policy_version,
            verification_context_hash=self.verification_context_hash,
        )
        return hmac.compare_digest(self.observation_hash, expected)

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
            "verification_id": self.verification_id,
            "claim_id": self.claim_id,
            "canonical_action_hash": self.canonical_action_hash,
            "expected_postcondition": self.expected_postcondition,
            "expected_digest": self.expected_digest,
            "executor_principal_id": self.executor_principal_id,
            "verifier_principal_id": self.verifier_principal_id,
            "policy_version": self.policy_version,
            "verification_context_hash": self.verification_context_hash,
            "consumed_at": self.consumed_at,
            "consumed_by_crossing_id": self.consumed_by_crossing_id,
            "consumed_by_claim_id": self.consumed_by_claim_id,
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
            verification_id=(str(data["verification_id"]) if data.get("verification_id") else None),
            claim_id=str(data["claim_id"]) if data.get("claim_id") else None,
            canonical_action_hash=(
                str(data["canonical_action_hash"]) if data.get("canonical_action_hash") else None
            ),
            expected_postcondition=(
                str(data["expected_postcondition"]) if data.get("expected_postcondition") else None
            ),
            expected_digest=(str(data["expected_digest"]) if data.get("expected_digest") else None),
            executor_principal_id=(
                str(data["executor_principal_id"]) if data.get("executor_principal_id") else None
            ),
            verifier_principal_id=(
                str(data["verifier_principal_id"]) if data.get("verifier_principal_id") else None
            ),
            policy_version=(str(data["policy_version"]) if data.get("policy_version") else None),
            verification_context_hash=(
                str(data["verification_context_hash"])
                if data.get("verification_context_hash")
                else None
            ),
            consumed_at=str(data["consumed_at"]) if data.get("consumed_at") else None,
            consumed_by_crossing_id=(
                str(data["consumed_by_crossing_id"])
                if data.get("consumed_by_crossing_id")
                else None
            ),
            consumed_by_claim_id=(
                str(data["consumed_by_claim_id"]) if data.get("consumed_by_claim_id") else None
            ),
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
    verification_context: VerificationContext | None = None,
    verification_id: str | None = None,
    claim_id: str | None = None,
    canonical_action_hash: str | None = None,
    expected_postcondition: str | None = None,
    expected_digest: str | None = None,
    executor_principal_id: str | None = None,
    verifier_principal_id: str | None = None,
    policy_version: str | None = None,
    verification_context_hash: str | None = None,
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

    if verification_context is not None:
        if not verification_context.verify_integrity():
            raise ObservationError("VerificationContext integrity check failed")
        crossing_id = verification_context.crossing_id
        verification_id = verification_context.verification_id
        claim_id = verification_context.claim_id
        canonical_action_hash = verification_context.canonical_action_hash
        expected_postcondition = verification_context.expected_postcondition
        expected_digest = verification_context.expected_digest
        executor_principal_id = verification_context.executor_principal_id
        verifier_principal_id = verification_context.verifier_principal_id
        policy_version = verification_context.policy_version
        verification_context_hash = verification_context.context_hash
        if observed_at is None:
            observed_at = verification_context.observed_at
        if expires_at is None:
            expires_at = verification_context.expires_at

    obs_id = observation_id or generate_observation_id()
    obs_version = "2" if verification_context_hash is not None else "1"
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
        verification_id=verification_id,
        claim_id=claim_id,
        canonical_action_hash=canonical_action_hash,
        expected_postcondition=expected_postcondition,
        expected_digest=expected_digest,
        executor_principal_id=executor_principal_id,
        verifier_principal_id=verifier_principal_id,
        policy_version=policy_version,
        verification_context_hash=verification_context_hash,
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
        verification_id=verification_id,
        claim_id=claim_id,
        canonical_action_hash=canonical_action_hash,
        expected_postcondition=expected_postcondition,
        expected_digest=expected_digest,
        executor_principal_id=executor_principal_id,
        verifier_principal_id=verifier_principal_id,
        policy_version=policy_version,
        verification_context_hash=verification_context_hash,
    )
