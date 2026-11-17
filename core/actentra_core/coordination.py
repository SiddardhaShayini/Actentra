"""Multi-agent resource coordination and conflict-locking contract for Actentra (Stage 3)."""

from __future__ import annotations

import fnmatch
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

_VALID_MODES: frozenset[str] = frozenset({"exclusive", "shared"})
_VALID_STATUSES: frozenset[str] = frozenset({"active", "released", "expired"})
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

LeaseMode = Literal["exclusive", "shared"]
LeaseStatus = Literal["active", "released", "expired"]


class CoordinationError(ValueError):
    """Base error for multi-agent coordination violations."""


class ResourceConflictError(CoordinationError):
    """Raised when an action conflicts with an active exclusive lease held by another agent."""


class LeaseNotFoundError(CoordinationError):
    """Raised when a requested lease record does not exist."""


class LeaseExpiredError(CoordinationError):
    """Raised when an operation is attempted on an expired lease."""


def generate_lease_id() -> str:
    """Generate a 26-character Crockford Base32 ID with 'lease_' prefix."""
    ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand_bytes = os.urandom(10)
    value = (ts_ms << 80) | int.from_bytes(rand_bytes, "big")
    chars = ["0"] * 26
    for i in range(25, -1, -1):
        chars[i] = _CROCKFORD[value & 0x1F]
        value >>= 5
    return f"lease_{''.join(chars)}"


def utc_iso(ts: float | None = None) -> str:
    """Format UTC timestamp as ISO-8601 string with millisecond precision."""
    dt = datetime.fromtimestamp(ts, UTC) if ts is not None else datetime.now(UTC)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(iso_str: str) -> float:
    """Parse ISO-8601 string to unix timestamp in seconds."""
    clean = iso_str.replace("Z", "+00:00")
    return datetime.fromisoformat(clean).timestamp()


def resource_pattern_matches(pattern: str, target: str) -> bool:
    """Check if a resource matches a pattern, supporting wildcards and path normalization."""
    p_norm = pattern.strip().replace("\\", "/")
    t_norm = target.strip().replace("\\", "/")

    # Windows paths are case-insensitive
    if p_norm.lower().startswith("path:") and t_norm.lower().startswith("path:"):
        p_norm = p_norm.lower()
        t_norm = t_norm.lower()

    if p_norm == t_norm:
        return True

    # Wildcard matching (e.g. path:C:/work/** or path:C:/work/*)
    if "*" in p_norm:
        # Standardize ** for fnmatch
        fn_pattern = p_norm.replace("**", "*")
        return fnmatch.fnmatchcase(t_norm, fn_pattern)

    # Prefix directory match: path:C:/dir/ matches path:C:/dir/subdir/file.txt
    return bool(p_norm.endswith("/") and t_norm.startswith(p_norm))


def compute_lease_hash(
    *,
    lease_id: str,
    lease_version: str,
    resource: str,
    owner_agent_id: str,
    session_id: str,
    mode: str,
    status: str,
    acquired_at: str,
    expires_at: str,
    metadata: dict[str, Any],
) -> str:
    """Compute deterministic SHA-256 canonical hash of the lease record."""
    payload = {
        "lease_id": lease_id,
        "lease_version": lease_version,
        "resource": resource,
        "owner_agent_id": owner_agent_id,
        "session_id": session_id,
        "mode": mode,
        "status": status,
        "acquired_at": acquired_at,
        "expires_at": expires_at,
        "metadata": metadata,
    }
    return hash_canonical(payload)


@dataclass(frozen=True, slots=True)
class ResourceLease:
    """Durable record of an acquired resource lease for multi-agent coordination."""

    lease_id: str
    lease_version: str
    resource: str
    owner_agent_id: str
    session_id: str
    mode: LeaseMode
    status: LeaseStatus
    acquired_at: str
    expires_at: str
    lease_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_active(self, now: float | None = None) -> bool:
        """Return True if lease status is 'active' and expires_at has not elapsed."""
        if self.status != "active":
            return False
        curr = now if now is not None else time.time()
        try:
            return curr < parse_iso(self.expires_at)
        except Exception:
            return False

    def matches_resource(self, target_resource: str) -> bool:
        """Check if this lease covers the given target resource."""
        return resource_pattern_matches(self.resource, target_resource)

    def verify_integrity(self) -> bool:
        """Verify that lease_hash strictly matches computed canonical payload hash."""
        expected = compute_lease_hash(
            lease_id=self.lease_id,
            lease_version=self.lease_version,
            resource=self.resource,
            owner_agent_id=self.owner_agent_id,
            session_id=self.session_id,
            mode=self.mode,
            status=self.status,
            acquired_at=self.acquired_at,
            expires_at=self.expires_at,
            metadata=self.metadata,
        )
        return self.lease_hash == expected

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation matching lease.v1.schema.json."""
        return {
            "lease_id": self.lease_id,
            "lease_version": self.lease_version,
            "resource": self.resource,
            "owner_agent_id": self.owner_agent_id,
            "session_id": self.session_id,
            "mode": self.mode,
            "status": self.status,
            "acquired_at": self.acquired_at,
            "expires_at": self.expires_at,
            "lease_hash": self.lease_hash,
            "metadata": dict(self.metadata),
        }


def build_lease(
    *,
    resource: str,
    owner_agent_id: str,
    session_id: str,
    mode: LeaseMode = "exclusive",
    ttl_seconds: float = 60.0,
    lease_id: str | None = None,
    now: float | None = None,
    metadata: dict[str, Any] | None = None,
) -> ResourceLease:
    """Construct, validate, and hash a new ResourceLease record."""
    lid = lease_id or generate_lease_id()
    if not (lid.startswith("lease_") and len(lid) == 32):
        raise CoordinationError(f"Invalid lease ID format: {lid!r}")

    agent = canonicalize_unicode(owner_agent_id.strip())
    if not agent or len(agent) > 128:
        raise CoordinationError("owner_agent_id must be 1-128 characters")

    sess = canonicalize_unicode(session_id.strip())
    if not sess or len(sess) > 128:
        raise CoordinationError("session_id must be 1-128 characters")

    if mode not in _VALID_MODES:
        raise CoordinationError(f"Invalid lease mode: {mode!r}; expected one of {_VALID_MODES}")

    res_clean = resource.strip()
    if not res_clean or len(res_clean) > 512:
        raise CoordinationError("resource must be 1-512 characters")

    # If it's a specific resource without wildcard, canonicalize it
    if "*" not in res_clean and "?" not in res_clean:
        with_scheme = res_clean if ":" in res_clean else f"path:{res_clean}"
        norm_resource = canonicalize_resource(with_scheme)
    else:
        norm_resource = res_clean.replace("\\", "/")

    curr_ts = now if now is not None else time.time()
    acq_iso = utc_iso(curr_ts)
    exp_iso = utc_iso(curr_ts + max(1.0, ttl_seconds))
    meta = dict(metadata or {})

    l_hash = compute_lease_hash(
        lease_id=lid,
        lease_version="1",
        resource=norm_resource,
        owner_agent_id=agent,
        session_id=sess,
        mode=mode,
        status="active",
        acquired_at=acq_iso,
        expires_at=exp_iso,
        metadata=meta,
    )

    return ResourceLease(
        lease_id=lid,
        lease_version="1",
        resource=norm_resource,
        owner_agent_id=agent,
        session_id=sess,
        mode=mode,
        status="active",
        acquired_at=acq_iso,
        expires_at=exp_iso,
        lease_hash=l_hash,
        metadata=meta,
    )
