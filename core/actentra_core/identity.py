"""Explicit identity, trust boundaries, and authority model for Actentra (Phase 1).

Provides a strict separation between:
- claimed identity: untrusted caller-supplied metadata (e.g. agent_id in payload or headers)
- authenticated identity: verified transport/credential principal (cryptographic signatures,
  bearer tokens, or local process)
- delegated identity: explicitly authorized, cryptographically and registry-bound authority
  from a parent principal
- effective execution principal: the verified, authorized identity under which the operation
  actually runs
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.x509.oid import NameOID

from actentra_core.canonicalize import canonicalize_json, canonicalize_unicode


class PrincipalType(StrEnum):
    """Authority tier of the calling principal."""

    LOCAL_PROCESS = "local_process"
    AUTHENTICATED_OPERATOR = "authenticated_operator"
    AUTHENTICATED_AGENT = "authenticated_agent"
    UNAUTHENTICATED_CALLER = "unauthenticated_caller"
    DELEGATED_AGENT = "delegated_agent"
    HUMAN_APPROVER = "human_approver"
    EXECUTOR = "executor"


_RESERVED_SYSTEM_IDENTIFIERS = frozenset(
    {"system", "kernel", "admin", "root", "actentra_internal", "policy_kernel"}
)

DEFAULT_OPERATOR_SCOPES: tuple[str, ...] = ("*",)
DEFAULT_APPROVER_SCOPES: tuple[str, ...] = ("crossings:read", "crossings:approve", "receipts:read")
DEFAULT_AGENT_SCOPES: tuple[str, ...] = (
    "crossings:propose",
    "crossings:execute",
    "crossings:claim",
    "crossings:outcome",
    "crossings:read",
    "handoffs:create",
    "handoffs:advance",
    "handoffs:verify",
    "leases:acquire",
    "leases:release",
)
DEFAULT_LOOPBACK_SCOPES: tuple[str, ...] = (
    "crossings:propose",
    "crossings:read",
    "handoffs:create",
    "handoffs:advance",
    "handoffs:verify",
    "leases:acquire",
    "leases:release",
    "crossings:approve",
    "crossings:execute",
    "crossings:claim",
    "crossings:outcome",
    "system:admin",
)


class IdentitySecurityError(PermissionError):
    """Raised when an unauthenticated caller attempts to claim reserved or elevated identity."""


@dataclass(frozen=True, slots=True)
class DelegationGrant:
    """Explicitly authorized, cryptographically verifiable delegation of authority."""

    grant_id: str
    delegator_id: str
    delegatee_id: str
    allowed_agents: tuple[str, ...]
    scopes: tuple[str, ...]
    parent_grant_id: str | None = None
    revoked: bool = False
    expires_at: float | None = None
    issued_at: float | None = None
    issuer: str | None = None
    version: int = 1
    audience: str | None = None
    depth: int = 0
    max_depth: int = 1
    nonce: str | None = None
    signature: str | None = None
    revoked_at: float | None = None
    revoked_by: str | None = None
    revocation_reason: str | None = None

    def is_valid(
        self,
        at_time: float | None = None,
        expected_audience: str | None = None,
    ) -> bool:
        """Check whether grant is active, not revoked, not expired, and matches audience/depth."""
        if self.revoked:
            return False
        now = at_time if at_time is not None else time.time()
        if self.expires_at is not None and now > self.expires_at:
            return False
        if self.issued_at is not None and self.issued_at > (now + 60.0):
            return False  # Clock skew protection against future-dated grants
        if expected_audience is not None and self.audience is not None:
            clean_expected = canonicalize_unicode(expected_audience).strip().lower()
            clean_aud = canonicalize_unicode(self.audience).strip().lower()
            if clean_aud != clean_expected:
                return False
        return self.depth <= self.max_depth

    def has_scope(self, scope: str) -> bool:
        """Check whether grant permits the specified permission scope."""
        if "*" in self.scopes:
            return True
        if scope in self.scopes:
            return True
        if ":" in scope:
            prefix = scope.split(":", 1)[0]
            if f"{prefix}:*" in self.scopes:
                return True
        return False

    def is_agent_allowed(self, agent_id: str) -> bool:
        """Validate if this grant permits asserting the specified agent_id."""
        clean = canonicalize_unicode(agent_id).strip().lower()
        if not clean:
            return False
        if "*" in self.allowed_agents:
            return True
        return clean in (a.lower() for a in self.allowed_agents)

    def payload_bytes(self) -> bytes:
        """Deterministic canonical bytes representation for Ed25519 signature verification."""
        data = {
            "grant_id": self.grant_id,
            "delegator_id": self.delegator_id,
            "delegatee_id": self.delegatee_id,
            "allowed_agents": sorted(list(self.allowed_agents)),
            "scopes": sorted(list(self.scopes)),
            "parent_grant_id": self.parent_grant_id,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "issuer": self.issuer,
            "version": self.version,
            "audience": self.audience,
            "depth": self.depth,
            "max_depth": self.max_depth,
            "nonce": self.nonce,
        }
        return canonicalize_json(data).encode("utf-8")

    def verify_signature(self, pubkey_pem: bytes) -> tuple[bool, str]:
        """Verify the cryptographic Ed25519 signature of this grant."""
        if not self.signature:
            return False, "Delegation grant is unsigned"
        try:
            loaded_pub = load_pem_public_key(pubkey_pem)
        except Exception as exc:
            return False, f"Failed to load Ed25519 public key: {exc}"
        if not isinstance(loaded_pub, Ed25519PublicKey):
            return False, "Public key must be Ed25519"
        try:
            sig_bytes = base64.b64decode(self.signature)
            loaded_pub.verify(sig_bytes, self.payload_bytes())
        except (InvalidSignature, ValueError) as exc:
            return False, f"Cryptographic signature invalid: {exc}"
        return True, "Signature valid"

    def to_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "delegator_id": self.delegator_id,
            "delegatee_id": self.delegatee_id,
            "allowed_agents": list(self.allowed_agents),
            "scopes": list(self.scopes),
            "parent_grant_id": self.parent_grant_id,
            "revoked": self.revoked,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "issuer": self.issuer,
            "version": self.version,
            "audience": self.audience,
            "depth": self.depth,
            "max_depth": self.max_depth,
            "nonce": self.nonce,
            "signature": self.signature,
            "revoked_at": self.revoked_at,
            "revoked_by": self.revoked_by,
            "revocation_reason": self.revocation_reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DelegationGrant:
        raw_allowed = data.get("allowed_agents", ())
        allowed_tuple = (
            tuple(str(a) for a in raw_allowed) if isinstance(raw_allowed, (list, tuple)) else ()
        )
        raw_scopes = data.get("scopes", ())
        scopes_tuple = (
            tuple(str(s) for s in raw_scopes) if isinstance(raw_scopes, (list, tuple)) else ()
        )
        return cls(
            grant_id=str(data["grant_id"]),
            delegator_id=str(data["delegator_id"]),
            delegatee_id=str(data["delegatee_id"]),
            allowed_agents=allowed_tuple,
            scopes=scopes_tuple,
            parent_grant_id=str(data["parent_grant_id"])
            if data.get("parent_grant_id") is not None
            else None,
            revoked=bool(data.get("revoked", False)),
            expires_at=float(data["expires_at"]) if data.get("expires_at") is not None else None,
            issued_at=float(data["issued_at"]) if data.get("issued_at") is not None else None,
            issuer=str(data["issuer"]) if data.get("issuer") is not None else None,
            version=int(data.get("version", 1)),
            audience=str(data["audience"]) if data.get("audience") is not None else None,
            depth=int(data.get("depth", 0)),
            max_depth=int(data.get("max_depth", 1)),
            nonce=str(data["nonce"]) if data.get("nonce") is not None else None,
            signature=str(data["signature"]) if data.get("signature") is not None else None,
            revoked_at=float(data["revoked_at"]) if data.get("revoked_at") is not None else None,
            revoked_by=str(data["revoked_by"]) if data.get("revoked_by") is not None else None,
            revocation_reason=str(data["revocation_reason"])
            if data.get("revocation_reason") is not None
            else None,
        )


class DelegationRegistry:
    """Thread-safe registry managing delegation grants, lifecycle, and strict principal binding."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grants: dict[str, DelegationGrant] = {}

    def register_grant(
        self,
        *,
        delegator: CallerContext,
        delegatee_id: str,
        allowed_agents: tuple[str, ...] | list[str],
        scopes: tuple[str, ...] | list[str],
        grant_id: str | None = None,
        ttl_seconds: float | None = None,
        audience: str | None = None,
        max_depth: int = 1,
        nonce: str | None = None,
        signature: str | None = None,
        issuer: str | None = None,
    ) -> DelegationGrant:
        """Register a new delegation grant from an authenticated delegator."""
        if not delegator.authenticated:
            raise IdentitySecurityError("Unauthenticated caller cannot delegate authority")

        clean_delegatee = canonicalize_unicode(delegatee_id).strip().lower()
        if not clean_delegatee:
            raise IdentitySecurityError("Delegatee identifier cannot be empty")
        if clean_delegatee in _RESERVED_SYSTEM_IDENTIFIERS:
            raise IdentitySecurityError(
                f"Cannot delegate to reserved system identifier '{delegatee_id}'"
            )

        # Scopes attenuation check: Child cannot receive scopes delegator does not possess
        scopes_tuple = tuple(scopes)
        for s in scopes_tuple:
            if not delegator.has_scope(s):
                raise IdentitySecurityError(
                    f"Delegation scope violation: delegator '{delegator.principal_id}' "
                    f"lacks scope '{s}' and cannot delegate it"
                )

        # Agent authority check: Child cannot represent agents delegator cannot represent
        agents_tuple = tuple(allowed_agents)
        for a in agents_tuple:
            if not delegator.is_agent_allowed(a):
                raise IdentitySecurityError(
                    f"Delegation agent violation: delegator '{delegator.principal_id}' "
                    f"is not authorized for agent '{a}' and cannot delegate it"
                )

        now = time.time()
        expires_at = (now + ttl_seconds) if ttl_seconds is not None and ttl_seconds > 0 else None

        # Nested delegation tracking and depth limits
        depth = 1
        parent_grant_id = None
        if delegator.delegation_grant_id is not None or delegator.delegated_by is not None:
            # The delegator is acting under a delegation grant
            parent_grant = (
                self.get_grant(delegator.delegation_grant_id)
                if delegator.delegation_grant_id
                else self.find_active_grant(
                    delegator_id=delegator.delegated_by or "",
                    delegatee_id=delegator.principal_id,
                )
            )
            if parent_grant is None or not parent_grant.is_valid(at_time=now):
                raise IdentitySecurityError("Parent delegation grant is invalid or revoked")
            if parent_grant.depth >= parent_grant.max_depth:
                raise IdentitySecurityError(
                    f"Delegation depth limit exceeded: depth {parent_grant.depth} "
                    f"reaches or exceeds max_depth {parent_grant.max_depth}"
                )
            depth = parent_grant.depth + 1
            max_depth = min(max_depth, parent_grant.max_depth)
            parent_grant_id = parent_grant.grant_id
            if parent_grant.expires_at is not None:
                expires_at = (
                    min(expires_at, parent_grant.expires_at)
                    if expires_at is not None
                    else parent_grant.expires_at
                )
            for s in scopes_tuple:
                if not parent_grant.has_scope(s):
                    raise IdentitySecurityError(
                        f"Delegation scope violation: child '{clean_delegatee}' has scope '{s}' "
                        f"which exceeds parent grant '{parent_grant.grant_id}'"
                    )
            for a in agents_tuple:
                if not parent_grant.is_agent_allowed(a):
                    raise IdentitySecurityError(
                        f"Delegation agent violation: child '{clean_delegatee}' has "
                        f"allowed agent '{a}' which exceeds parent grant '{parent_grant.grant_id}'"
                    )

        gid = grant_id or f"grant-{uuid.uuid4().hex[:12]}"
        grant_nonce = nonce or uuid.uuid4().hex
        grant_issuer = issuer or canonicalize_unicode(delegator.principal_id).strip()

        grant = DelegationGrant(
            grant_id=gid,
            delegator_id=canonicalize_unicode(delegator.principal_id).strip(),
            delegatee_id=clean_delegatee,
            allowed_agents=agents_tuple,
            scopes=scopes_tuple,
            parent_grant_id=parent_grant_id,
            revoked=False,
            expires_at=expires_at,
            issued_at=now,
            issuer=grant_issuer,
            version=1,
            audience=canonicalize_unicode(audience).strip() if audience else None,
            depth=depth,
            max_depth=max_depth,
            nonce=grant_nonce,
            signature=signature,
        )

        with self._lock:
            self._grants[gid] = grant
        return grant

    def register_grant_direct(self, grant: DelegationGrant) -> None:
        """Directly insert a validated grant (used for server config pre-population)."""
        with self._lock:
            self._grants[grant.grant_id] = grant

    def validate_grant_binding(
        self,
        grant: DelegationGrant | str,
        *,
        authenticated_delegatee_id: str,
        authenticated_delegator_id: str | None = None,
        required_scopes: tuple[str, ...] | list[str] | None = None,
        required_agent: str | None = None,
        audience: str | None = None,
        at_time: float | None = None,
    ) -> DelegationGrant:
        """Validate that a grant strictly binds to the authenticated principals and is active.

        Enforces:
        - grant.delegator_id == authenticated_delegator.id (if specified)
        - grant.delegatee_id == authenticated_delegatee.id
        - Grant is unrevoked, unexpired, and within depth limits
        - All parent grants in the delegation chain are valid and unrevoked
        """
        now = at_time if at_time is not None else time.time()
        resolved_grant: DelegationGrant
        with self._lock:
            if isinstance(grant, str):
                g = self._grants.get(grant)
                if g is None:
                    raise IdentitySecurityError(f"Delegation grant '{grant}' not found")
                resolved_grant = g
            else:
                resolved_grant = grant

        # 1. Check revocation
        if resolved_grant.revoked:
            raise IdentitySecurityError(
                f"Delegation grant from '{resolved_grant.delegator_id}' to "
                f"'{resolved_grant.delegatee_id}' is invalid or revoked"
            )

        # 2. Check expiration
        if resolved_grant.expires_at is not None and now > resolved_grant.expires_at:
            raise IdentitySecurityError(
                f"Delegation grant from '{resolved_grant.delegator_id}' to "
                f"'{resolved_grant.delegatee_id}' is invalid or revoked"
            )

        # 3. Check audience
        if audience is not None and resolved_grant.audience is not None:
            clean_expected = canonicalize_unicode(audience).strip().lower()
            clean_aud = canonicalize_unicode(resolved_grant.audience).strip().lower()
            if clean_aud != clean_expected:
                raise IdentitySecurityError(
                    f"Delegation grant '{resolved_grant.grant_id}' audience mismatch: "
                    f"expected '{audience}', got '{resolved_grant.audience}'"
                )

        # 4. Check general validity (clock skew, depth)
        if not resolved_grant.is_valid(at_time=now, expected_audience=audience):
            raise IdentitySecurityError(
                f"Delegation grant '{resolved_grant.grant_id}' is invalid or expired"
            )

        # 5. Strict delegatee binding: The authenticated caller MUST be the intended delegatee
        clean_auth_del = canonicalize_unicode(authenticated_delegatee_id).strip().lower()
        if resolved_grant.delegatee_id.lower() != clean_auth_del:
            raise IdentitySecurityError(
                f"Grant binding violation: grant '{resolved_grant.grant_id}' was issued to "
                f"delegatee '{resolved_grant.delegatee_id}', "
                f"but presented by '{authenticated_delegatee_id}'"
            )

        # 6. Strict delegator binding: If delegator is claimed, it MUST match the grant
        if authenticated_delegator_id is not None:
            clean_claimed_parent = canonicalize_unicode(authenticated_delegator_id).strip().lower()
            if resolved_grant.delegator_id.lower() != clean_claimed_parent:
                raise IdentitySecurityError(
                    f"Grant binding violation: grant '{resolved_grant.grant_id}' was issued by "
                    f"delegator '{resolved_grant.delegator_id}', but caller asserted "
                    f"delegator '{authenticated_delegator_id}'"
                )

        # 6. Check required scopes if specified
        if required_scopes:
            for sc in required_scopes:
                if not resolved_grant.has_scope(sc):
                    raise IdentitySecurityError(
                        f"Delegation scope violation: grant '{resolved_grant.grant_id}' "
                        f"lacks scope '{sc}'"
                    )

        # 7. Check required agent if specified
        if required_agent and not resolved_grant.is_agent_allowed(required_agent):
            raise IdentitySecurityError(
                f"Delegation agent violation: grant '{resolved_grant.grant_id}' "
                f"does not allow agent '{required_agent}'"
            )

        # 8. Recursive parent chain validation for nested delegations
        if resolved_grant.parent_grant_id:
            with self._lock:
                parent = self._grants.get(resolved_grant.parent_grant_id)
            if parent is None or not parent.is_valid(at_time=now):
                raise IdentitySecurityError(
                    f"Delegation chain broken: parent grant '{resolved_grant.parent_grant_id}' "
                    f"is invalid or revoked"
                )
            if parent.revoked:
                raise IdentitySecurityError(
                    f"Delegation chain broken: parent grant '{resolved_grant.parent_grant_id}' "
                    f"has been revoked"
                )
            # Recursively validate parent grant binding up the chain
            self.validate_grant_binding(
                parent,
                authenticated_delegatee_id=parent.delegatee_id,
                at_time=now,
            )

        return resolved_grant

    def revoke_grant(
        self,
        grant_id: str,
        revoker: CallerContext,
        reason: str = "manual_revocation",
    ) -> bool:
        """Revoke an active delegation grant and recursively cascade revocation down the chain."""
        if not revoker.authenticated:
            raise IdentitySecurityError("Unauthenticated caller cannot revoke delegation")

        now = time.time()
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None:
                return False

            clean_revoker = canonicalize_unicode(revoker.principal_id).strip().lower()
            clean_delegator = canonicalize_unicode(grant.delegator_id).strip().lower()

            # Check if revoker is delegator, trusted operator, or an upstream ancestor
            is_authorized = revoker.is_trusted_operator or clean_revoker == clean_delegator
            if not is_authorized:
                # Walk up parent chain to check if revoker is an ancestor delegator
                curr = grant
                while curr.parent_grant_id:
                    parent = self._grants.get(curr.parent_grant_id)
                    if parent is None:
                        break
                    if parent.delegator_id.lower() == clean_revoker:
                        is_authorized = True
                        break
                    curr = parent

            if not is_authorized:
                raise IdentitySecurityError(
                    f"Principal '{revoker.principal_id}' is not authorized to "
                    f"revoke grant '{grant_id}' issued by '{grant.delegator_id}'"
                )

            # Revoke target grant
            self._grants[grant_id] = DelegationGrant(
                grant_id=grant.grant_id,
                delegator_id=grant.delegator_id,
                delegatee_id=grant.delegatee_id,
                allowed_agents=grant.allowed_agents,
                scopes=grant.scopes,
                parent_grant_id=grant.parent_grant_id,
                revoked=True,
                expires_at=grant.expires_at,
                issued_at=grant.issued_at,
                issuer=grant.issuer,
                version=grant.version,
                audience=grant.audience,
                depth=grant.depth,
                max_depth=grant.max_depth,
                nonce=grant.nonce,
                signature=grant.signature,
                revoked_at=now,
                revoked_by=revoker.principal_id,
                revocation_reason=reason,
            )

            # Cascading revocation: revoke all child grants recursively
            self._cascade_revocation_under_lock(grant_id, revoker_id=revoker.principal_id, now=now)
            return True

    def _cascade_revocation_under_lock(self, parent_id: str, revoker_id: str, now: float) -> None:
        """Revoke all descendants of parent_id under existing lock."""
        to_revoke: list[str] = [
            gid
            for gid, g in self._grants.items()
            if g.parent_grant_id == parent_id and not g.revoked
        ]
        for child_id in to_revoke:
            child = self._grants[child_id]
            self._grants[child_id] = DelegationGrant(
                grant_id=child.grant_id,
                delegator_id=child.delegator_id,
                delegatee_id=child.delegatee_id,
                allowed_agents=child.allowed_agents,
                scopes=child.scopes,
                parent_grant_id=child.parent_grant_id,
                revoked=True,
                expires_at=child.expires_at,
                issued_at=child.issued_at,
                issuer=child.issuer,
                version=child.version,
                audience=child.audience,
                depth=child.depth,
                max_depth=child.max_depth,
                nonce=child.nonce,
                signature=child.signature,
                revoked_at=now,
                revoked_by=revoker_id,
                revocation_reason=f"Cascading revocation from parent grant '{parent_id}'",
            )
            # Recurse down descendants
            self._cascade_revocation_under_lock(child_id, revoker_id=revoker_id, now=now)

    def get_grant(self, grant_id: str) -> DelegationGrant | None:
        with self._lock:
            return self._grants.get(grant_id)

    def find_active_grant(
        self,
        *,
        delegator_id: str,
        delegatee_id: str,
        target_agent: str | None = None,
        audience: str | None = None,
        at_time: float | None = None,
    ) -> DelegationGrant | None:
        """Find an active, valid grant matching delegator and delegatee."""
        clean_delegator = canonicalize_unicode(delegator_id).strip().lower()
        clean_delegatee = canonicalize_unicode(delegatee_id).strip().lower()
        clean_target = canonicalize_unicode(target_agent).strip().lower() if target_agent else None
        now = at_time if at_time is not None else time.time()
        with self._lock:
            for grant in self._grants.values():
                if not grant.is_valid(at_time=now, expected_audience=audience):
                    continue
                if grant.delegator_id.lower() != clean_delegator:
                    continue
                if grant.delegatee_id.lower() != clean_delegatee:
                    continue
                if clean_target and not grant.is_agent_allowed(clean_target):
                    continue
                return grant
        return None

    def cleanup_expired_grants(self, at_time: float | None = None) -> int:
        """Remove expired grants from the registry (retention cleanup)."""
        now = at_time if at_time is not None else time.time()
        with self._lock:
            expired_ids = [
                gid
                for gid, g in self._grants.items()
                if g.expires_at is not None and now > g.expires_at
            ]
            for gid in expired_ids:
                del self._grants[gid]
            return len(expired_ids)

    def clear(self) -> None:
        with self._lock:
            self._grants.clear()


_DEFAULT_DELEGATION_REGISTRY = DelegationRegistry()


def get_default_delegation_registry() -> DelegationRegistry:
    return _DEFAULT_DELEGATION_REGISTRY


def reset_default_delegation_registry() -> None:
    _DEFAULT_DELEGATION_REGISTRY.clear()


def issue_signed_delegation_grant(
    *,
    delegator: CallerContext,
    delegatee_id: str,
    allowed_agents: tuple[str, ...] | list[str],
    scopes: tuple[str, ...] | list[str],
    privkey_pem: bytes,
    ttl_seconds: float = 3600.0,
    audience: str | None = None,
    max_depth: int = 1,
    parent_grant: DelegationGrant | None = None,
    grant_id: str | None = None,
) -> DelegationGrant:
    """Issue and cryptographically sign an Ed25519 capability delegation grant."""
    if not delegator.authenticated:
        raise IdentitySecurityError("Unauthenticated caller cannot delegate authority")

    clean_delegatee = canonicalize_unicode(delegatee_id).strip().lower()
    if not clean_delegatee:
        raise IdentitySecurityError("Delegatee identifier cannot be empty")
    if clean_delegatee in _RESERVED_SYSTEM_IDENTIFIERS:
        raise IdentitySecurityError(
            f"Cannot delegate to reserved system identifier '{delegatee_id}'"
        )

    # Scopes attenuation check: Child cannot receive scopes delegator lacks
    scopes_tuple = tuple(scopes)
    for s in scopes_tuple:
        if not delegator.has_scope(s):
            raise IdentitySecurityError(
                f"Delegation scope violation: delegator '{delegator.principal_id}' "
                f"lacks scope '{s}' and cannot delegate it"
            )

    # Agent authority check: Child cannot represent agents delegator cannot represent
    agents_tuple = tuple(allowed_agents)
    for a in agents_tuple:
        if not delegator.is_agent_allowed(a):
            raise IdentitySecurityError(
                f"Delegation agent violation: delegator '{delegator.principal_id}' "
                f"is not authorized for agent '{a}' and cannot delegate it"
            )

    gid = grant_id or f"grant-{uuid.uuid4().hex[:12]}"
    now = time.time()
    expires_at = (now + ttl_seconds) if ttl_seconds > 0 else None

    depth = 0
    parent_gid = None
    if parent_grant is not None:
        if not parent_grant.is_valid(at_time=now):
            raise IdentitySecurityError("Parent delegation grant is invalid or revoked")
        if parent_grant.depth + 1 > parent_grant.max_depth:
            raise IdentitySecurityError(
                f"Delegation depth limit exceeded: "
                f"{parent_grant.depth + 1} > {parent_grant.max_depth}"
            )
        depth = parent_grant.depth + 1
        max_depth = min(max_depth, parent_grant.max_depth)
        parent_gid = parent_grant.grant_id
        if parent_grant.expires_at is not None:
            expires_at = (
                min(expires_at, parent_grant.expires_at)
                if expires_at is not None
                else parent_grant.expires_at
            )
        for s in scopes_tuple:
            if not parent_grant.has_scope(s):
                raise IdentitySecurityError(
                    f"Delegation scope violation: scope '{s}' exceeds parent grant"
                )
        for a in agents_tuple:
            if not parent_grant.is_agent_allowed(a):
                raise IdentitySecurityError(
                    f"Delegation agent violation: agent '{a}' exceeds parent grant"
                )

    unsigned = DelegationGrant(
        grant_id=gid,
        delegator_id=canonicalize_unicode(delegator.principal_id).strip(),
        delegatee_id=clean_delegatee,
        allowed_agents=agents_tuple,
        scopes=scopes_tuple,
        parent_grant_id=parent_gid,
        revoked=False,
        expires_at=expires_at,
        issued_at=now,
        issuer=canonicalize_unicode(delegator.principal_id).strip(),
        version=1,
        audience=canonicalize_unicode(audience).strip() if audience else None,
        depth=depth,
        max_depth=max_depth,
        nonce=uuid.uuid4().hex,
        signature=None,
    )

    try:
        loaded_key = load_pem_private_key(privkey_pem, password=None)
    except Exception as exc:
        raise IdentitySecurityError(f"Failed to load Ed25519 private key: {exc}") from exc

    if not isinstance(loaded_key, Ed25519PrivateKey):
        raise IdentitySecurityError("Private key must be Ed25519")

    sig_bytes = loaded_key.sign(unsigned.payload_bytes())
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    return DelegationGrant(
        grant_id=unsigned.grant_id,
        delegator_id=unsigned.delegator_id,
        delegatee_id=unsigned.delegatee_id,
        allowed_agents=unsigned.allowed_agents,
        scopes=unsigned.scopes,
        parent_grant_id=unsigned.parent_grant_id,
        revoked=False,
        expires_at=unsigned.expires_at,
        issued_at=unsigned.issued_at,
        issuer=unsigned.issuer,
        version=unsigned.version,
        audience=unsigned.audience,
        depth=unsigned.depth,
        max_depth=unsigned.max_depth,
        nonce=unsigned.nonce,
        signature=sig_b64,
    )


def verify_signed_delegation_grant(
    grant: DelegationGrant,
    pubkey_pem: bytes,
    *,
    expected_delegatee: str | None = None,
    expected_delegator: str | None = None,
    expected_audience: str | None = None,
    at_time: float | None = None,
) -> tuple[bool, str]:
    """Verify cryptographic Ed25519 signature, expiration, and principal binding of a grant."""
    if not grant.signature:
        return False, "Delegation grant is unsigned"

    try:
        loaded_pub = load_pem_public_key(pubkey_pem)
    except Exception as exc:
        return False, f"Failed to load Ed25519 public key: {exc}"

    if not isinstance(loaded_pub, Ed25519PublicKey):
        return False, "Public key must be Ed25519"

    try:
        sig_bytes = base64.b64decode(grant.signature)
        loaded_pub.verify(sig_bytes, grant.payload_bytes())
    except (InvalidSignature, ValueError) as exc:
        return False, f"Cryptographic signature invalid: {exc}"

    if grant.revoked:
        return False, f"Delegation grant '{grant.grant_id}' has been revoked"

    now = at_time if at_time is not None else time.time()
    if grant.expires_at is not None and now > grant.expires_at:
        return False, f"Delegation grant '{grant.grant_id}' has expired"

    if expected_delegatee is not None:
        clean_exp_del = canonicalize_unicode(expected_delegatee).strip().lower()
        if grant.delegatee_id.lower() != clean_exp_del:
            return (
                False,
                f"Delegatee mismatch: expected '{expected_delegatee}', got '{grant.delegatee_id}'",
            )

    if expected_delegator is not None:
        clean_exp_par = canonicalize_unicode(expected_delegator).strip().lower()
        if grant.delegator_id.lower() != clean_exp_par:
            return (
                False,
                f"Delegator mismatch: expected '{expected_delegator}', got '{grant.delegator_id}'",
            )

    if expected_audience is not None and grant.audience is not None:
        clean_exp_aud = canonicalize_unicode(expected_audience).strip().lower()
        if grant.audience.lower() != clean_exp_aud:
            return (
                False,
                f"Audience mismatch: expected '{expected_audience}', got '{grant.audience}'",
            )

    return True, "Delegation grant valid"


@dataclass(frozen=True, slots=True)
class CallerContext:
    """Authenticated caller context establishing immutable trust boundaries."""

    principal_type: PrincipalType
    principal_id: str
    authenticated: bool
    trust_domain: str
    scopes: tuple[str, ...] = ()
    allowed_agents: tuple[str, ...] = ()
    delegated_by: str | None = None
    delegation_grant_id: str | None = None
    claimed_identity: str | None = None
    authenticated_principal_id: str | None = None
    delegation_grant: DelegationGrant | None = None
    audience: str | None = None

    @property
    def authenticated_identity(self) -> str:
        """The immutable authenticated transport principal identity."""
        return self.authenticated_principal_id or self.principal_id

    @property
    def delegated_principal_id(self) -> str | None:
        """The verified delegating principal ID, if executing under delegation."""
        return self.delegated_by

    @property
    def effective_principal_id(self) -> str:
        """The canonical verified execution principal under whose authority the action runs."""
        if self.claimed_identity and self.is_agent_allowed(self.claimed_identity):
            return self.claimed_identity
        return self.principal_id

    @property
    def is_trusted_operator(self) -> bool:
        """True if the caller is an authenticated operator, local process, or holds system:admin."""
        if "system:admin" in self.scopes or "*" in self.scopes:
            return True
        return self.authenticated and self.principal_type in (
            PrincipalType.LOCAL_PROCESS,
            PrincipalType.AUTHENTICATED_OPERATOR,
        )

    @property
    def is_approver(self) -> bool:
        """True if caller has human approver or operator authority to approve crossings."""
        if self.is_trusted_operator:
            return True
        if self.authenticated and self.principal_type == PrincipalType.HUMAN_APPROVER:
            return self.has_scope("crossings:approve")
        if not self.authenticated and self.trust_domain == "local_loopback":
            return self.has_scope("crossings:approve")
        return False

    def has_scope(self, scope: str) -> bool:
        """Check whether principal holds the specified permission scope."""
        if "*" in self.scopes or "system:admin" in self.scopes:
            return True
        if scope in self.scopes:
            return True
        if ":" in scope:
            prefix = scope.split(":", 1)[0]
            if f"{prefix}:*" in self.scopes:
                return True
        return False

    def is_agent_allowed(self, agent_id: str) -> bool:
        """Validate if this principal has verified authority to act as or on behalf of agent_id."""
        clean = canonicalize_unicode(agent_id).strip().lower()
        if not clean:
            return False

        # 1. Trusted operators and local processes can act as any agent
        # (unless explicitly restricted by allowed_agents without wildcard)
        if self.is_trusted_operator:
            if not self.allowed_agents or "*" in self.allowed_agents:
                return True
            return clean in (a.lower() for a in self.allowed_agents)

        # 2. Authenticated agents or delegated principals:
        if self.authenticated:
            if "*" in self.allowed_agents:
                return True
            if clean in (a.lower() for a in self.allowed_agents):
                return True
            clean_principal = canonicalize_unicode(self.principal_id).strip().lower()
            return clean == clean_principal

        # 3. Unauthenticated callers:
        # Cannot assert reserved system identities
        if clean in _RESERVED_SYSTEM_IDENTIFIERS:
            return False
        # If caller specified client_identity, must match
        clean_principal = canonicalize_unicode(self.principal_id).strip().lower()
        if (
            clean_principal
            and not clean_principal.startswith("loopback@")
            and not clean_principal.startswith("anonymous@")
        ):
            return clean == clean_principal
        # In loopback development mode without client_identity
        return self.trust_domain == "local_loopback"

    def validate_identity_claims(
        self,
        claimed_agent_id: str,
        claimed_provenance_trust: str | None = None,
    ) -> None:
        """Validate that caller is permitted to assert the claimed identity and trust."""
        clean_agent = canonicalize_unicode(claimed_agent_id).strip().lower()
        if not clean_agent:
            raise IdentitySecurityError("Agent identity claim cannot be empty")

        if not self.is_trusted_operator:
            # Unauthenticated or non-operator caller cannot impersonate system/admin identities
            if clean_agent in _RESERVED_SYSTEM_IDENTIFIERS:
                raise IdentitySecurityError(
                    f"Caller '{self.principal_id}' cannot "
                    f"claim reserved system identity '{claimed_agent_id}'"
                )
            # Unauthenticated caller cannot assert 'trusted' provenance directly
            if claimed_provenance_trust == "trusted":
                raise IdentitySecurityError(
                    f"Caller '{self.principal_id}' is not an authenticated operator "
                    "and cannot assert trust='trusted'"
                )

        if not self.is_agent_allowed(claimed_agent_id):
            raise IdentitySecurityError(
                f"Principal '{self.principal_id}' is not authorized to "
                f"assert identity '{claimed_agent_id}'"
            )

    def bound_agent_id(self, requested_agent: str | None = None) -> str:
        """Bind or resolve effective agent identifier, failing closed if unauthorized."""
        if requested_agent and requested_agent.strip():
            clean = canonicalize_unicode(requested_agent).strip()
            if not self.is_agent_allowed(clean):
                raise IdentitySecurityError(
                    f"Principal '{self.principal_id}' is not authorized to "
                    f"bind agent '{requested_agent}'"
                )
            return clean
        if self.principal_type == PrincipalType.AUTHENTICATED_AGENT:
            return self.principal_id
        if len(self.allowed_agents) == 1 and self.allowed_agents[0] != "*":
            return self.allowed_agents[0]
        return self.principal_id or "default-agent"

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_type": self.principal_type.value,
            "principal_id": self.principal_id,
            "authenticated": self.authenticated,
            "trust_domain": self.trust_domain,
            "scopes": list(self.scopes),
            "allowed_agents": list(self.allowed_agents),
            "delegated_by": self.delegated_by,
            "delegation_grant_id": self.delegation_grant_id,
            "claimed_identity": self.claimed_identity,
            "authenticated_principal_id": self.authenticated_principal_id,
            "effective_principal_id": self.effective_principal_id,
            "audience": self.audience,
        }


def make_local_caller_context(principal_id: str = "local_operator") -> CallerContext:
    """Create trusted caller context for in-process SDK execution."""
    return CallerContext(
        principal_type=PrincipalType.LOCAL_PROCESS,
        principal_id=principal_id,
        authenticated=True,
        trust_domain="local_boundary",
        scopes=("*",),
        allowed_agents=("*",),
        authenticated_principal_id=principal_id,
    )


def _find_parent_in_principals(
    parent_id: str,
    token_principals: Mapping[str, Any],
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Find scopes and allowed_agents of a parent principal in token_principals mapping."""
    clean_parent = canonicalize_unicode(parent_id).strip().lower()
    for entry in token_principals.values():
        if isinstance(entry, CallerContext):
            if entry.principal_id.lower() == clean_parent:
                return entry.scopes, entry.allowed_agents
        elif isinstance(entry, str):
            if entry.lower() == clean_parent:
                return DEFAULT_AGENT_SCOPES, (entry,)
        elif isinstance(entry, dict):
            pid = str(entry.get("principal_id", "")).strip().lower()
            if pid == clean_parent:
                raw_scopes = entry.get("scopes", DEFAULT_AGENT_SCOPES)
                scopes_tuple = tuple(raw_scopes) if isinstance(raw_scopes, (list, tuple)) else ()
                raw_allowed = entry.get("allowed_agents")
                allowed_tuple = (
                    tuple(raw_allowed) if isinstance(raw_allowed, (list, tuple)) else (pid,)
                )
                return scopes_tuple, allowed_tuple
    return None


def _normalize_fingerprint(fp: str) -> str:
    clean = canonicalize_unicode(fp).strip().lower()
    if clean.startswith("sha256:"):
        clean = clean[7:]
    clean = clean.replace(":", "")
    return f"sha256:{clean}"


@dataclass(frozen=True, slots=True)
class CertificateIdentity:
    """Validated X.509 transport identity extracted from an authenticated TLS socket."""

    sha256_fingerprint: str
    subject_cn: str | None
    san_uris: tuple[str, ...]
    san_dns: tuple[str, ...]
    issuer_cn: str | None
    issuer_dn: str
    serial_number: str
    not_valid_before: datetime
    not_valid_after: datetime

    def is_currently_valid(self, at_time: float | None = None) -> bool:
        """Return True if certificate validity window covers at_time."""
        now_dt = (
            datetime.fromtimestamp(at_time, UTC) if at_time is not None else datetime.now(UTC)
        )
        return self.not_valid_before <= now_dt <= self.not_valid_after


def extract_certificate_identity(der_bytes: bytes) -> CertificateIdentity:
    """Extract canonical CertificateIdentity from DER-encoded X.509 peer certificate."""
    if not der_bytes:
        raise IdentitySecurityError("Empty TLS peer certificate")
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception as exc:
        raise IdentitySecurityError(f"Malformed TLS peer certificate: {exc}") from exc

    fp = f"sha256:{hashlib.sha256(der_bytes).hexdigest().lower()}"

    subject_cn: str | None = None
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        subject_cn = str(cn_attrs[0].value)

    issuer_cn: str | None = None
    issuer_cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if issuer_cn_attrs:
        issuer_cn = str(issuer_cn_attrs[0].value)

    san_uris: list[str] = []
    san_dns: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_uris = [
            str(u).strip() for u in san_ext.get_values_for_type(x509.UniformResourceIdentifier)
        ]
        san_dns = [str(d).strip().lower() for d in san_ext.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        pass

    return CertificateIdentity(
        sha256_fingerprint=fp,
        subject_cn=subject_cn,
        san_uris=tuple(san_uris),
        san_dns=tuple(san_dns),
        issuer_cn=issuer_cn,
        issuer_dn=cert.issuer.rfc4514_string(),
        serial_number=format(cert.serial_number, "x"),
        not_valid_before=cert.not_valid_before_utc,
        not_valid_after=cert.not_valid_after_utc,
    )


@dataclass(frozen=True, slots=True)
class CertificatePrincipalBinding:
    """Explicit trusted mapping between an X.509 client certificate and an app principal."""

    principal_id: str
    principal_type: PrincipalType = PrincipalType.AUTHENTICATED_AGENT
    fingerprints: tuple[str, ...] = ()
    san_uris: tuple[str, ...] = ()
    allowed_issuers: tuple[str, ...] = ()
    scopes: tuple[str, ...] = DEFAULT_AGENT_SCOPES
    allowed_agents: tuple[str, ...] = ()
    trust_domain: str = "mtls"
    revoked: bool = False
    expires_at: float | None = None


class MTLSPrincipalRegistry:
    """Thread-safe registry binding mTLS client certificates to application principals."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._bindings: dict[str, CertificatePrincipalBinding] = {}
        self._revoked_fingerprints: set[str] = set()
        self._audit_events: list[dict[str, Any]] = []

    def _record_event(self, event_type: str, **details: Any) -> None:
        self._audit_events.append(
            {"ts": time.time(), "event": event_type, **details}
        )
        if len(self._audit_events) > 2000:
            self._audit_events = self._audit_events[-2000:]

    def audit_events(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(ev) for ev in self._audit_events]

    def register_binding(self, binding: CertificatePrincipalBinding) -> None:
        """Register or update a principal's certificate binding, rejecting ambiguous claims."""
        clean_pid = canonicalize_unicode(binding.principal_id).strip()
        if not clean_pid:
            raise IdentitySecurityError("Certificate binding requires non-empty principal_id")
        norm_fps = tuple(_normalize_fingerprint(fp) for fp in binding.fingerprints if fp)
        norm_uris = tuple(canonicalize_unicode(u).strip() for u in binding.san_uris if u)
        if not norm_fps and not norm_uris:
            raise IdentitySecurityError(
                f"Certificate binding for '{clean_pid}' must specify fingerprints or san_uris"
            )
        allowed_agents = binding.allowed_agents or (clean_pid,)
        normalized = CertificatePrincipalBinding(
            principal_id=clean_pid,
            principal_type=binding.principal_type,
            fingerprints=norm_fps,
            san_uris=norm_uris,
            allowed_issuers=tuple(binding.allowed_issuers),
            scopes=tuple(binding.scopes),
            allowed_agents=tuple(allowed_agents),
            trust_domain=binding.trust_domain,
            revoked=binding.revoked,
            expires_at=binding.expires_at,
        )
        with self._lock:
            for existing_pid, existing in self._bindings.items():
                if existing_pid.lower() == clean_pid.lower() or existing.revoked:
                    continue
                if set(norm_fps) & set(existing.fingerprints):
                    raise IdentitySecurityError(
                        f"Ambiguous certificate fingerprint mapping: already bound to "
                        f"'{existing.principal_id}'"
                    )
                if set(norm_uris) & set(existing.san_uris):
                    raise IdentitySecurityError(
                        f"Ambiguous SAN URI mapping: already bound to '{existing.principal_id}'"
                    )
            self._bindings[clean_pid.lower()] = normalized
            self._record_event(
                "cert_binding_registered",
                principal_id=clean_pid,
                fingerprints=list(norm_fps),
                san_uris=list(norm_uris),
            )

    @classmethod
    def from_dict(cls, mapping: Mapping[str, Any]) -> MTLSPrincipalRegistry:
        """Build MTLSPrincipalRegistry from configuration dictionary keyed by principal_id."""
        reg = cls()
        for key, raw in mapping.items():
            if isinstance(raw, CertificatePrincipalBinding):
                reg.register_binding(raw)
                continue
            if not isinstance(raw, Mapping):
                raise IdentitySecurityError(
                    f"Invalid cert_principals entry for '{key}'"
                )
            pid = str(raw.get("principal_id", key))
            fps_raw = raw.get("fingerprints") or (
                [raw["fingerprint"]] if raw.get("fingerprint") else []
            )
            uris_raw = raw.get("san_uris") or (
                [raw["san_uri"]] if raw.get("san_uri") else []
            )
            issuers_raw = raw.get("allowed_issuers") or ()
            scopes_raw = raw.get("scopes", DEFAULT_AGENT_SCOPES)
            agents_raw = raw.get("allowed_agents") or (pid,)
            p_type = PrincipalType(raw.get("principal_type", PrincipalType.AUTHENTICATED_AGENT))
            reg.register_binding(
                CertificatePrincipalBinding(
                    principal_id=pid,
                    principal_type=p_type,
                    fingerprints=tuple(str(f) for f in fps_raw),
                    san_uris=tuple(str(u) for u in uris_raw),
                    allowed_issuers=tuple(str(i) for i in issuers_raw),
                    scopes=tuple(str(s) for s in scopes_raw),
                    allowed_agents=tuple(str(a) for a in agents_raw),
                    trust_domain=str(raw.get("trust_domain", "mtls")),
                    revoked=bool(raw.get("revoked", False)),
                    expires_at=(
                        float(raw["expires_at"]) if raw.get("expires_at") is not None else None
                    ),
                )
            )
        return reg

    def revoke_certificate(self, fingerprint: str, *, reason: str = "manual_revocation") -> None:
        """Revoke a specific certificate fingerprint immediately."""
        norm = _normalize_fingerprint(fingerprint)
        with self._lock:
            self._revoked_fingerprints.add(norm)
            self._record_event("cert_revoked", fingerprint=norm, reason=reason)

    def revoke_principal(self, principal_id: str, *, reason: str = "manual_revocation") -> bool:
        """Revoke all certificate bindings for a principal."""
        clean = canonicalize_unicode(principal_id).strip().lower()
        with self._lock:
            existing = self._bindings.get(clean)
            if existing is None:
                return False
            for fp in existing.fingerprints:
                self._revoked_fingerprints.add(fp)
            self._bindings[clean] = CertificatePrincipalBinding(
                principal_id=existing.principal_id,
                principal_type=existing.principal_type,
                fingerprints=existing.fingerprints,
                san_uris=existing.san_uris,
                allowed_issuers=existing.allowed_issuers,
                scopes=existing.scopes,
                allowed_agents=existing.allowed_agents,
                trust_domain=existing.trust_domain,
                revoked=True,
                expires_at=existing.expires_at,
            )
            self._record_event(
                "principal_cert_revoked", principal_id=existing.principal_id, reason=reason
            )
            return True

    def rotate_certificate(
        self,
        principal_id: str,
        *,
        new_fingerprint: str | None = None,
        new_san_uri: str | None = None,
        old_fingerprint: str | None = None,
        revoke_old: bool = True,
    ) -> CertificatePrincipalBinding:
        """Rotate a principal's certificate, optionally revoking the old fingerprint."""
        clean = canonicalize_unicode(principal_id).strip().lower()
        with self._lock:
            existing = self._bindings.get(clean)
            if existing is None:
                raise IdentitySecurityError(
                    f"Cannot rotate certificate: principal '{principal_id}' not registered"
                )
            if existing.revoked:
                raise IdentitySecurityError(
                    f"Cannot rotate certificate for revoked principal '{principal_id}'"
                )
            fps = list(existing.fingerprints)
            if revoke_old:
                if old_fingerprint:
                    norm_old = _normalize_fingerprint(old_fingerprint)
                    self._revoked_fingerprints.add(norm_old)
                    fps = [f for f in fps if f != norm_old]
                else:
                    for fp in fps:
                        self._revoked_fingerprints.add(fp)
                    fps = []
            if new_fingerprint:
                norm_new = _normalize_fingerprint(new_fingerprint)
                if norm_new in self._revoked_fingerprints:
                    raise IdentitySecurityError("Cannot rotate to an already-revoked certificate")
                if norm_new not in fps:
                    fps.append(norm_new)

            uris = list(existing.san_uris)
            if new_san_uri and new_san_uri not in uris:
                uris.append(canonicalize_unicode(new_san_uri).strip())

            updated = CertificatePrincipalBinding(
                principal_id=existing.principal_id,
                principal_type=existing.principal_type,
                fingerprints=tuple(fps),
                san_uris=tuple(uris),
                allowed_issuers=existing.allowed_issuers,
                scopes=existing.scopes,
                allowed_agents=existing.allowed_agents,
                trust_domain=existing.trust_domain,
                revoked=False,
                expires_at=existing.expires_at,
            )
            self._bindings[clean] = updated
            self._record_event(
                "cert_rotated",
                principal_id=existing.principal_id,
                new_fingerprint=new_fingerprint,
                revoke_old=revoke_old,
            )
            return updated

    def resolve_certificate(
        self,
        cert_id: CertificateIdentity,
        *,
        at_time: float | None = None,
    ) -> CertificatePrincipalBinding:
        """Resolve an authenticated TLS peer certificate to its unique principal binding."""
        now = at_time if at_time is not None else time.time()
        if not cert_id.is_currently_valid(at_time=now):
            raise IdentitySecurityError(
                f"Client certificate '{cert_id.sha256_fingerprint}' is expired or not yet valid"
            )

        with self._lock:
            if cert_id.sha256_fingerprint in self._revoked_fingerprints:
                self._record_event(
                    "cert_rejected_revoked", fingerprint=cert_id.sha256_fingerprint
                )
                raise IdentitySecurityError(
                    f"Client certificate '{cert_id.sha256_fingerprint}' has been revoked"
                )

            matches: list[CertificatePrincipalBinding] = []
            for binding in self._bindings.values():
                fp_match = cert_id.sha256_fingerprint in binding.fingerprints
                uri_match = bool(set(cert_id.san_uris) & set(binding.san_uris))
                if fp_match or uri_match:
                    matches.append(binding)

            if len(matches) > 1:
                self._record_event(
                    "cert_rejected_ambiguous", fingerprint=cert_id.sha256_fingerprint
                )
                raise IdentitySecurityError(
                    f"Ambiguous certificate mapping for '{cert_id.sha256_fingerprint}'"
                )
            if not matches:
                self._record_event(
                    "cert_rejected_unknown",
                    fingerprint=cert_id.sha256_fingerprint,
                    san_uris=list(cert_id.san_uris),
                )
                raise IdentitySecurityError(
                    f"Client certificate '{cert_id.sha256_fingerprint}' is not registered "
                    "to any application principal"
                )

            binding = matches[0]
            if binding.revoked:
                raise IdentitySecurityError(
                    f"Certificate binding for principal '{binding.principal_id}' is revoked"
                )
            if binding.expires_at is not None and now > binding.expires_at:
                raise IdentitySecurityError(
                    f"Certificate binding for principal '{binding.principal_id}' has expired"
                )
            if binding.allowed_issuers:
                issuer_match = cert_id.issuer_dn in binding.allowed_issuers or (
                    cert_id.issuer_cn is not None and cert_id.issuer_cn in binding.allowed_issuers
                )
                if not issuer_match:
                    self._record_event(
                        "cert_rejected_issuer",
                        fingerprint=cert_id.sha256_fingerprint,
                        issuer=cert_id.issuer_dn,
                    )
                    raise IdentitySecurityError(
                        f"Client certificate issuer '{cert_id.issuer_dn}' is not authorized "
                        f"for principal '{binding.principal_id}'"
                    )
            return binding


def resolve_http_caller_context(
    *,
    headers: dict[str, str],
    expected_token: str | None = None,
    remote_addr: str = "127.0.0.1",
    token_principals: Mapping[str, Any] | None = None,
    delegation_registry: DelegationRegistry | None = None,
    client_cert: CertificateIdentity | None = None,
    cert_registry: MTLSPrincipalRegistry | None = None,
    require_client_cert: bool = False,
    enforce_strict_shared_token: bool = False,
) -> CallerContext:
    """Resolve caller context from HTTP headers, strictly verifying credentials and delegation."""
    auth_header = headers.get("authorization", "").strip()
    client_identity = headers.get("x-actentra-identity", "").strip()
    header_delegated_by = headers.get("x-actentra-delegated-by", "").strip() or None
    header_parent = headers.get("x-actentra-parent", "").strip() or None
    header_grant_id = headers.get("x-actentra-delegation-grant", "").strip() or None
    header_audience = headers.get("x-actentra-audience", "").strip() or None

    claimed_delegation = header_delegated_by or header_parent
    reg = delegation_registry or get_default_delegation_registry()
    has_server_auth = bool(
        (expected_token and expected_token.strip())
        or (token_principals is not None and len(token_principals) > 0)
    )

    # 0. Validate transport-layer mTLS identity if required or present
    cert_binding: CertificatePrincipalBinding | None = None
    if require_client_cert and client_cert is None:
        raise IdentitySecurityError("Mutual TLS client certificate required and none was provided")
    if client_cert is not None:
        if not client_cert.is_currently_valid():
            raise IdentitySecurityError(
                f"Client certificate '{client_cert.sha256_fingerprint}' is expired or not yet valid"
            )
        if cert_registry is not None:
            cert_binding = cert_registry.resolve_certificate(client_cert)

    def _bind_transport_identity(ctx: CallerContext) -> CallerContext:
        """Bind application CallerContext strictly to validated mTLS CertificatePrincipalBinding."""
        if client_cert is None:
            return ctx
        if cert_binding is not None:
            auth_pid = ctx.authenticated_principal_id or ctx.principal_id
            if auth_pid.lower() != cert_binding.principal_id.lower():
                raise IdentitySecurityError(
                    f"mTLS identity binding mismatch: client certificate belongs to "
                    f"'{cert_binding.principal_id}', but Bearer token belongs to '{auth_pid}'"
                )
            # Attenuate scopes & allowed_agents to intersection of token and cert binding
            if "*" in cert_binding.scopes:
                bound_scopes = ctx.scopes
            elif "*" in ctx.scopes:
                bound_scopes = cert_binding.scopes
            else:
                bound_scopes = tuple(s for s in ctx.scopes if s in cert_binding.scopes)

            if "*" in cert_binding.allowed_agents:
                bound_agents = ctx.allowed_agents
            elif "*" in ctx.allowed_agents:
                bound_agents = cert_binding.allowed_agents
            else:
                cert_ag_low = {a.lower() for a in cert_binding.allowed_agents}
                bound_agents = tuple(a for a in ctx.allowed_agents if a.lower() in cert_ag_low)

            return CallerContext(
                principal_type=ctx.principal_type,
                principal_id=cert_binding.principal_id,
                authenticated=ctx.authenticated,
                trust_domain=cert_binding.trust_domain,
                scopes=bound_scopes,
                allowed_agents=bound_agents,
                delegated_by=ctx.delegated_by,
                delegation_grant_id=ctx.delegation_grant_id,
                claimed_identity=ctx.claimed_identity,
                authenticated_principal_id=cert_binding.principal_id,
                delegation_grant=ctx.delegation_grant,
                audience=ctx.audience,
            )
        return ctx

    # 1. Process Bearer token if presented
    if auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer ") :].strip()
        if not token:
            raise IdentitySecurityError("Bearer token cannot be empty")

        # When server authentication is configured, token MUST match server config
        if has_server_auth:
            # Check configured token_principals mapping using constant-time matching
            matched_entry = None
            if token_principals:
                for cand_tok, entry in token_principals.items():
                    if hmac.compare_digest(token, str(cand_tok)):
                        matched_entry = entry
                        break

            if matched_entry is not None:
                mapped = matched_entry
                if isinstance(mapped, dict):
                    if mapped.get("revoked"):
                        raise IdentitySecurityError("Bearer token has been revoked")
                    exp = mapped.get("expires_at")
                    if exp is not None and time.time() > float(exp):
                        raise IdentitySecurityError("Bearer token has expired")
                    req_fp = mapped.get("cert_fingerprint")
                    if req_fp is not None:
                        if client_cert is None:
                            raise IdentitySecurityError(
                                "Token requires mTLS client certificate"
                            )
                        if _normalize_fingerprint(str(req_fp)) != client_cert.sha256_fingerprint:
                            raise IdentitySecurityError(
                                "mTLS identity binding mismatch: certificate fingerprint does "
                                "not match token principal binding"
                            )
                    req_uri = mapped.get("san_uri")
                    if req_uri is not None and (
                        client_cert is None or str(req_uri) not in client_cert.san_uris
                    ):
                        raise IdentitySecurityError(
                            "mTLS identity binding mismatch: certificate SAN URI does not "
                            "match token principal binding"
                        )

                if isinstance(mapped, CallerContext):
                    ctx = mapped
                elif isinstance(mapped, str):
                    ctx = CallerContext(
                        principal_type=PrincipalType.AUTHENTICATED_AGENT,
                        principal_id=mapped,
                        authenticated=True,
                        trust_domain="gateway_agent",
                        scopes=DEFAULT_AGENT_SCOPES,
                        allowed_agents=(mapped,),
                        delegated_by=None,
                        authenticated_principal_id=mapped,
                    )
                elif isinstance(mapped, dict):
                    p_type = PrincipalType(
                        mapped.get("principal_type", PrincipalType.AUTHENTICATED_AGENT)
                    )
                    p_id = mapped.get("principal_id", f"agent@{remote_addr}")
                    raw_scopes = mapped.get("scopes", DEFAULT_AGENT_SCOPES)
                    scopes_tuple = (
                        tuple(raw_scopes) if isinstance(raw_scopes, (list, tuple)) else ()
                    )
                    allowed = mapped.get("allowed_agents")
                    allowed_tuple = (
                        tuple(allowed) if isinstance(allowed, (list, tuple)) else (p_id,)
                    )
                    cfg_delegated_by = mapped.get("delegated_by")

                    # If delegation is configured in token_principals, validate parent attenuation
                    if cfg_delegated_by:
                        parent_info = _find_parent_in_principals(
                            cfg_delegated_by, token_principals or {}
                        )
                        if parent_info is not None:
                            parent_scopes, parent_allowed = parent_info
                            if "*" not in parent_scopes:
                                for sc in scopes_tuple:
                                    if sc not in parent_scopes:
                                        raise IdentitySecurityError(
                                            f"Delegation scope violation: child '{p_id}' has scope "
                                            f"'{sc}' which exceeds parent '{cfg_delegated_by}'"
                                        )
                            if "*" not in parent_allowed:
                                for ag in allowed_tuple:
                                    if ag.lower() != p_id.lower() and ag.lower() not in (
                                        pa.lower() for pa in parent_allowed
                                    ):
                                        raise IdentitySecurityError(
                                            f"Delegation agent violation: child '{p_id}' has "
                                            f"allowed agent '{ag}' not authorized for parent "
                                            f"'{cfg_delegated_by}'"
                                        )

                        # Auto-register configured delegation grant in registry
                        grant_id = f"cfg-grant-{p_id}-{cfg_delegated_by}"
                        reg.register_grant_direct(
                            DelegationGrant(
                                grant_id=grant_id,
                                delegator_id=cfg_delegated_by,
                                delegatee_id=p_id,
                                allowed_agents=allowed_tuple,
                                scopes=scopes_tuple,
                                issuer="system_config",
                                version=1,
                            )
                        )

                    ctx = CallerContext(
                        principal_type=p_type,
                        principal_id=p_id,
                        authenticated=bool(mapped.get("authenticated", True)),
                        trust_domain=mapped.get("trust_domain", "gateway_agent"),
                        scopes=scopes_tuple,
                        allowed_agents=allowed_tuple,
                        delegated_by=cfg_delegated_by,
                        authenticated_principal_id=p_id,
                    )
                else:
                    raise IdentitySecurityError("Invalid token principal mapping configuration")

                # Validate caller-supplied delegation headers against authenticated context
                if claimed_delegation or header_grant_id:
                    if ctx.delegated_by:
                        if (
                            claimed_delegation
                            and ctx.delegated_by.lower() != claimed_delegation.lower()
                        ):
                            raise IdentitySecurityError(
                                f"Conflicting delegation: header asserts '{claimed_delegation}' "
                                f"but principal is configured with delegator '{ctx.delegated_by}'"
                            )
                        if header_grant_id:
                            grant = reg.validate_grant_binding(
                                header_grant_id,
                                authenticated_delegatee_id=ctx.authenticated_identity,
                                authenticated_delegator_id=ctx.delegated_by,
                                audience=header_audience,
                            )
                    else:
                        # Dynamic delegation: strictly validate grant binding
                        if header_grant_id:
                            grant = reg.validate_grant_binding(
                                header_grant_id,
                                authenticated_delegatee_id=ctx.authenticated_identity,
                                authenticated_delegator_id=claimed_delegation,
                                audience=header_audience,
                            )
                        else:
                            active_grant = reg.find_active_grant(
                                delegator_id=claimed_delegation or "",
                                delegatee_id=ctx.authenticated_identity,
                                audience=header_audience,
                            )
                            if active_grant is None:
                                raise IdentitySecurityError(
                                    f"Unauthorized caller-supplied delegation: "
                                    f"'{ctx.authenticated_identity}' is not an authorized "
                                    f"delegate of '{claimed_delegation}'"
                                )
                            grant = reg.validate_grant_binding(
                                active_grant,
                                authenticated_delegatee_id=ctx.authenticated_identity,
                                authenticated_delegator_id=claimed_delegation,
                                audience=header_audience,
                            )

                        # Scope attenuation: cannot receive more authority than granted
                        effective_grant_scopes = tuple(
                            dict.fromkeys(s for s in ctx.scopes if grant.has_scope(s))
                        )
                        new_allowed = tuple(
                            dict.fromkeys((*ctx.allowed_agents, *grant.allowed_agents))
                        )
                        ctx = CallerContext(
                            principal_type=PrincipalType.DELEGATED_AGENT,
                            principal_id=ctx.principal_id,
                            authenticated=True,
                            trust_domain=ctx.trust_domain,
                            scopes=effective_grant_scopes,
                            allowed_agents=new_allowed,
                            delegated_by=grant.delegator_id,
                            delegation_grant_id=grant.grant_id,
                            claimed_identity=client_identity or None,
                            authenticated_principal_id=ctx.authenticated_identity,
                            delegation_grant=grant,
                            audience=header_audience,
                        )

                if client_identity and not ctx.is_agent_allowed(client_identity):
                    raise IdentitySecurityError(
                        f"Conflicting identity claim: authenticated principal '{ctx.principal_id}' "
                        f"cannot assert identity '{client_identity}'"
                    )
                return _bind_transport_identity(ctx)

            # Check configured shared expected_token using constant-time comparison
            if expected_token and hmac.compare_digest(token, expected_token):
                if cert_binding is not None:
                    # Bind shared token strictly to the authenticated mTLS cert principal
                    if client_identity and not (
                        "*" in cert_binding.allowed_agents
                        or client_identity.lower()
                        in {a.lower() for a in cert_binding.allowed_agents}
                    ):
                        raise IdentitySecurityError(
                            f"Conflicting identity claim: cert principal "
                            f"'{cert_binding.principal_id}' cannot assert '{client_identity}'"
                        )
                    return CallerContext(
                        principal_type=cert_binding.principal_type,
                        principal_id=cert_binding.principal_id,
                        authenticated=True,
                        trust_domain=cert_binding.trust_domain,
                        scopes=cert_binding.scopes,
                        allowed_agents=cert_binding.allowed_agents,
                        claimed_identity=client_identity or None,
                        authenticated_principal_id=cert_binding.principal_id,
                    )
                if enforce_strict_shared_token:
                    fixed_pid = "shared-gateway-operator"
                    if client_identity and client_identity.lower() != fixed_pid:
                        raise IdentitySecurityError(
                            "Shared bearer token cannot impersonate distinct principal "
                            f"'{client_identity}' in remote/strict mode"
                        )
                    return CallerContext(
                        principal_type=PrincipalType.AUTHENTICATED_OPERATOR,
                        principal_id=fixed_pid,
                        authenticated=True,
                        trust_domain="gateway_operator",
                        scopes=DEFAULT_OPERATOR_SCOPES,
                        allowed_agents=("*",),
                        claimed_identity=client_identity or None,
                        authenticated_principal_id=fixed_pid,
                    )
                return CallerContext(
                    principal_type=PrincipalType.AUTHENTICATED_OPERATOR,
                    principal_id=client_identity or f"token-operator@{remote_addr}",
                    authenticated=True,
                    trust_domain="gateway_operator",
                    scopes=DEFAULT_OPERATOR_SCOPES,
                    allowed_agents=("*",),
                    claimed_identity=client_identity or None,
                    authenticated_principal_id=client_identity or f"token-operator@{remote_addr}",
                )

            # When server authentication is configured, any other token fails closed
            raise IdentitySecurityError(
                "Invalid or unauthorized bearer token: does not match configured "
                "authentication secret"
            )

        # When server authentication is NOT configured: development / loopback mode
        # Structured operator and approver tokens are NEVER permitted without server configuration
        if token.startswith("operator:"):
            raise IdentitySecurityError(
                "Structured operator tokens cannot grant operator privileges without "
                "server configuration"
            )
        if token.startswith("approver:"):
            raise IdentitySecurityError(
                "Structured approver tokens cannot grant approver privileges without "
                "server configuration"
            )

        # Development agent tokens (agent:<id>) are permitted ONLY on local loopback
        if token.startswith("agent:"):
            if remote_addr in ("127.0.0.1", "::1", "localhost"):
                agent_name = token[len("agent:") :].strip()
                if not agent_name:
                    raise IdentitySecurityError("Agent identity in bearer token cannot be empty")
                if agent_name.lower() in _RESERVED_SYSTEM_IDENTIFIERS:
                    raise IdentitySecurityError(
                        f"Cannot claim reserved system identity '{agent_name}'"
                    )

                # Caller-supplied delegation check: must be verified in registry with strict binding
                allowed_tuple = (agent_name,)
                active_delegator: str | None = None
                dev_grant_id: str | None = None
                matched_grant: DelegationGrant | None = None
                dev_scopes = DEFAULT_AGENT_SCOPES

                if claimed_delegation or header_grant_id:
                    if header_grant_id:
                        grant = reg.validate_grant_binding(
                            header_grant_id,
                            authenticated_delegatee_id=agent_name,
                            authenticated_delegator_id=claimed_delegation,
                            audience=header_audience,
                        )
                    else:
                        active_grant = reg.find_active_grant(
                            delegator_id=claimed_delegation or "",
                            delegatee_id=agent_name,
                            audience=header_audience,
                        )
                        if active_grant is None:
                            raise IdentitySecurityError(
                                f"Unauthorized caller-supplied delegation: '{agent_name}' "
                                f"is not an authorized delegate of '{claimed_delegation}'"
                            )
                        grant = reg.validate_grant_binding(
                            active_grant,
                            authenticated_delegatee_id=agent_name,
                            authenticated_delegator_id=claimed_delegation,
                            audience=header_audience,
                        )

                    allowed_tuple = tuple(dict.fromkeys((agent_name, *grant.allowed_agents)))
                    dev_scopes = tuple(
                        dict.fromkeys(s for s in DEFAULT_AGENT_SCOPES if grant.has_scope(s))
                    )
                    active_delegator = grant.delegator_id
                    dev_grant_id = grant.grant_id
                    matched_grant = grant

                ctx = CallerContext(
                    principal_type=(
                        PrincipalType.DELEGATED_AGENT
                        if active_delegator
                        else PrincipalType.AUTHENTICATED_AGENT
                    ),
                    principal_id=agent_name,
                    authenticated=True,
                    trust_domain="gateway_agent",
                    scopes=dev_scopes,
                    allowed_agents=allowed_tuple,
                    delegated_by=active_delegator,
                    delegation_grant_id=dev_grant_id,
                    claimed_identity=client_identity or None,
                    authenticated_principal_id=agent_name,
                    delegation_grant=matched_grant,
                    audience=header_audience,
                )
                if client_identity and not ctx.is_agent_allowed(client_identity):
                    raise IdentitySecurityError(
                        f"Conflicting identity claim: authenticated agent '{agent_name}' "
                        f"cannot assert identity '{client_identity}'"
                    )
                return ctx
            else:
                raise IdentitySecurityError(
                    "Remote callers cannot use development agent tokens without "
                    "server configuration"
                )

        raise IdentitySecurityError("Invalid or unrecognized authentication token")

    # 2. No Bearer token provided
    if claimed_delegation or header_grant_id:
        raise IdentitySecurityError("Unauthenticated caller cannot assert delegated authority")

    # Pure mTLS certificate authentication (when no server Bearer token is configured)
    if cert_binding is not None and not has_server_auth:
        if client_identity and not (
            "*" in cert_binding.allowed_agents
            or client_identity.lower() in {a.lower() for a in cert_binding.allowed_agents}
        ):
            raise IdentitySecurityError(
                f"Conflicting identity claim: cert principal '{cert_binding.principal_id}' "
                f"cannot assert identity '{client_identity}'"
            )
        return CallerContext(
            principal_type=cert_binding.principal_type,
            principal_id=cert_binding.principal_id,
            authenticated=True,
            trust_domain=cert_binding.trust_domain,
            scopes=cert_binding.scopes,
            allowed_agents=cert_binding.allowed_agents,
            claimed_identity=client_identity or None,
            authenticated_principal_id=cert_binding.principal_id,
        )

    # In loopback mode without expected_token, classify as loopback caller
    if remote_addr in ("127.0.0.1", "::1", "localhost"):
        loop_scopes = (
            DEFAULT_LOOPBACK_SCOPES
            if not has_server_auth
            else ("crossings:propose", "crossings:read")
        )
        return CallerContext(
            principal_type=PrincipalType.UNAUTHENTICATED_CALLER,
            principal_id=client_identity or f"loopback@{remote_addr}",
            authenticated=False,
            trust_domain="local_loopback",
            scopes=loop_scopes,
            allowed_agents=(),
            claimed_identity=client_identity or None,
            authenticated_principal_id=None,
        )

    return CallerContext(
        principal_type=PrincipalType.UNAUTHENTICATED_CALLER,
        principal_id=client_identity or f"anonymous@{remote_addr}",
        authenticated=False,
        trust_domain="untrusted_network",
        scopes=(),
        allowed_agents=(),
        claimed_identity=client_identity or None,
        authenticated_principal_id=None,
    )
