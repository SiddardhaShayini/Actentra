"""Explicit identity, trust boundaries, and authority model for Actentra (V5).

Provides a strict separation between:
- caller-supplied metadata (e.g. agent_id, session_id claimed by HTTP payload)
- authenticated operator identity (verified credentials, tokens, or local in-process callers)
- trust domains and delegated authority
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from actentra_core.canonicalize import canonicalize_unicode


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
    """Explicitly authorized delegation of authority from a delegator to a delegatee."""

    grant_id: str
    delegator_id: str
    delegatee_id: str
    allowed_agents: tuple[str, ...]
    scopes: tuple[str, ...]
    parent_grant_id: str | None = None
    revoked: bool = False
    expires_at: float | None = None

    def is_valid(self, at_time: float | None = None) -> bool:
        """Check whether grant is active, not revoked, and not expired."""
        if self.revoked:
            return False
        if self.expires_at is not None:
            now = at_time if at_time is not None else time.time()
            if now > self.expires_at:
                return False
        return True

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
        }


class DelegationRegistry:
    """Thread-safe registry managing delegation grants and verification."""

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

        gid = grant_id or f"grant-{uuid.uuid4().hex[:12]}"
        now = time.time()
        expires_at = (now + ttl_seconds) if ttl_seconds is not None and ttl_seconds > 0 else None

        grant = DelegationGrant(
            grant_id=gid,
            delegator_id=canonicalize_unicode(delegator.principal_id).strip(),
            delegatee_id=clean_delegatee,
            allowed_agents=agents_tuple,
            scopes=scopes_tuple,
            revoked=False,
            expires_at=expires_at,
        )

        with self._lock:
            self._grants[gid] = grant
        return grant

    def register_grant_direct(self, grant: DelegationGrant) -> None:
        """Directly insert a validated grant (used for server config pre-population)."""
        with self._lock:
            self._grants[grant.grant_id] = grant

    def revoke_grant(self, grant_id: str, revoker: CallerContext) -> bool:
        """Revoke an active delegation grant. Only delegator or trusted operator can revoke."""
        if not revoker.authenticated:
            raise IdentitySecurityError("Unauthenticated caller cannot revoke delegation")

        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None:
                return False

            clean_revoker = canonicalize_unicode(revoker.principal_id).strip().lower()
            clean_delegator = canonicalize_unicode(grant.delegator_id).strip().lower()
            if not revoker.is_trusted_operator and clean_revoker != clean_delegator:
                raise IdentitySecurityError(
                    f"Principal '{revoker.principal_id}' is not authorized to "
                    f"revoke grant '{grant_id}' issued by '{grant.delegator_id}'"
                )

            self._grants[grant_id] = DelegationGrant(
                grant_id=grant.grant_id,
                delegator_id=grant.delegator_id,
                delegatee_id=grant.delegatee_id,
                allowed_agents=grant.allowed_agents,
                scopes=grant.scopes,
                parent_grant_id=grant.parent_grant_id,
                revoked=True,
                expires_at=grant.expires_at,
            )
            return True

    def get_grant(self, grant_id: str) -> DelegationGrant | None:
        with self._lock:
            return self._grants.get(grant_id)

    def find_active_grant(
        self,
        *,
        delegator_id: str,
        delegatee_id: str,
        target_agent: str | None = None,
    ) -> DelegationGrant | None:
        clean_delegator = canonicalize_unicode(delegator_id).strip().lower()
        clean_delegatee = canonicalize_unicode(delegatee_id).strip().lower()
        clean_target = canonicalize_unicode(target_agent).strip().lower() if target_agent else None
        now = time.time()
        with self._lock:
            for grant in self._grants.values():
                target_allowed = not clean_target or clean_target in (
                    a.lower() for a in grant.allowed_agents
                )
                if (
                    grant.is_valid(now)
                    and grant.delegator_id.lower() == clean_delegator
                    and grant.delegatee_id.lower() == clean_delegatee
                    and target_allowed
                ):
                    return grant
        return None

    def clear(self) -> None:
        with self._lock:
            self._grants.clear()


_DEFAULT_DELEGATION_REGISTRY = DelegationRegistry()


def get_default_delegation_registry() -> DelegationRegistry:
    return _DEFAULT_DELEGATION_REGISTRY


def reset_default_delegation_registry() -> None:
    _DEFAULT_DELEGATION_REGISTRY.clear()


@dataclass(frozen=True, slots=True)
class CallerContext:
    """Authenticated caller context establishing trust boundaries."""

    principal_type: PrincipalType
    principal_id: str
    authenticated: bool
    trust_domain: str
    scopes: tuple[str, ...] = ()
    allowed_agents: tuple[str, ...] = ()
    delegated_by: str | None = None
    delegation_grant_id: str | None = None

    @property
    def is_trusted_operator(self) -> bool:
        """True if the caller is an authenticated operator or local process."""
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
        """Bind or resolve effective agent identifier."""
        if requested_agent and requested_agent.strip():
            return requested_agent.strip()
        if self.principal_type == PrincipalType.AUTHENTICATED_AGENT:
            return self.principal_id
        return requested_agent or self.principal_id or "default-agent"

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
    )


def _find_parent_in_principals(
    parent_id: str,
    token_principals: dict[str, Any],
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


def resolve_http_caller_context(
    *,
    headers: dict[str, str],
    expected_token: str | None = None,
    remote_addr: str = "127.0.0.1",
    token_principals: dict[str, CallerContext | dict[str, Any] | str] | None = None,
    delegation_registry: DelegationRegistry | None = None,
) -> CallerContext:
    """Resolve caller context from HTTP headers, strictly verifying credentials and delegation."""
    auth_header = headers.get("authorization", "").strip()
    client_identity = headers.get("x-actentra-identity", "").strip()
    header_delegated_by = headers.get("x-actentra-delegated-by", "").strip() or None
    header_parent = headers.get("x-actentra-parent", "").strip() or None
    header_grant_id = headers.get("x-actentra-delegation-grant", "").strip() or None

    claimed_delegation = header_delegated_by or header_parent
    reg = delegation_registry or get_default_delegation_registry()
    has_server_auth = bool(
        (expected_token and expected_token.strip())
        or (token_principals is not None and len(token_principals) > 0)
    )

    # 1. Process Bearer token if presented
    if auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer ") :].strip()
        if not token:
            raise IdentitySecurityError("Bearer token cannot be empty")

        # When server authentication is configured, token MUST match server config
        if has_server_auth:
            # Check configured token_principals mapping
            if token_principals and token in token_principals:
                mapped = token_principals[token]
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
                        parent_info = _find_parent_in_principals(cfg_delegated_by, token_principals)
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
                    )
                else:
                    raise IdentitySecurityError(
                        f"Invalid token principal mapping for token '{token}'"
                    )

                # Validate caller-supplied delegation headers against authenticated context
                if claimed_delegation:
                    if ctx.delegated_by:
                        if ctx.delegated_by.lower() != claimed_delegation.lower():
                            raise IdentitySecurityError(
                                f"Conflicting delegation: header asserts '{claimed_delegation}' "
                                f"but principal is configured with delegator '{ctx.delegated_by}'"
                            )
                    else:
                        # Caller is asserting delegation via header: MUST be verified in registry
                        grant = (
                            reg.get_grant(header_grant_id)
                            if header_grant_id
                            else reg.find_active_grant(
                                delegator_id=claimed_delegation,
                                delegatee_id=ctx.principal_id,
                            )
                        )
                        if grant is not None and not grant.is_valid():
                            raise IdentitySecurityError(
                                f"Delegation grant from '{claimed_delegation}' to "
                                f"'{ctx.principal_id}' is invalid or revoked"
                            )
                        if grant is None:
                            raise IdentitySecurityError(
                                f"Unauthorized caller-supplied delegation: '{ctx.principal_id}' "
                                f"is not an authorized delegate of '{claimed_delegation}'"
                            )
                        # Add granted agents and record delegation
                        new_allowed = tuple(
                            dict.fromkeys((*ctx.allowed_agents, *grant.allowed_agents))
                        )
                        ctx = CallerContext(
                            principal_type=PrincipalType.DELEGATED_AGENT,
                            principal_id=ctx.principal_id,
                            authenticated=True,
                            trust_domain=ctx.trust_domain,
                            scopes=ctx.scopes,
                            allowed_agents=new_allowed,
                            delegated_by=claimed_delegation,
                            delegation_grant_id=grant.grant_id,
                        )

                if client_identity and not ctx.is_agent_allowed(client_identity):
                    raise IdentitySecurityError(
                        f"Conflicting identity claim: authenticated principal '{ctx.principal_id}' "
                        f"cannot assert identity '{client_identity}'"
                    )
                return ctx

            # Check configured shared expected_token
            if expected_token and token == expected_token:
                return CallerContext(
                    principal_type=PrincipalType.AUTHENTICATED_OPERATOR,
                    principal_id=client_identity or f"token-operator@{remote_addr}",
                    authenticated=True,
                    trust_domain="gateway_operator",
                    scopes=DEFAULT_OPERATOR_SCOPES,
                    allowed_agents=("*",),
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

                # Caller-supplied delegation check: must be verified in registry
                allowed_tuple = (agent_name,)
                active_delegator: str | None = None
                dev_grant_id: str | None = None
                if claimed_delegation:
                    grant = (
                        reg.get_grant(header_grant_id)
                        if header_grant_id
                        else reg.find_active_grant(
                            delegator_id=claimed_delegation,
                            delegatee_id=agent_name,
                        )
                    )
                    if grant is not None and not grant.is_valid():
                        raise IdentitySecurityError(
                            f"Delegation grant from '{claimed_delegation}' to '{agent_name}' "
                            "is invalid or revoked"
                        )
                    if grant is None:
                        raise IdentitySecurityError(
                            f"Unauthorized caller-supplied delegation: '{agent_name}' "
                            f"is not an authorized delegate of '{claimed_delegation}'"
                        )
                    allowed_tuple = tuple(dict.fromkeys((agent_name, *grant.allowed_agents)))
                    active_delegator = claimed_delegation
                    dev_grant_id = grant.grant_id

                ctx = CallerContext(
                    principal_type=(
                        PrincipalType.DELEGATED_AGENT
                        if active_delegator
                        else PrincipalType.AUTHENTICATED_AGENT
                    ),
                    principal_id=agent_name,
                    authenticated=True,
                    trust_domain="gateway_agent",
                    scopes=DEFAULT_AGENT_SCOPES,
                    allowed_agents=allowed_tuple,
                    delegated_by=active_delegator,
                    delegation_grant_id=dev_grant_id,
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
    if claimed_delegation:
        raise IdentitySecurityError("Unauthenticated caller cannot assert delegated authority")

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
        )

    return CallerContext(
        principal_type=PrincipalType.UNAUTHENTICATED_CALLER,
        principal_id=client_identity or f"anonymous@{remote_addr}",
        authenticated=False,
        trust_domain="untrusted_network",
        scopes=(),
        allowed_agents=(),
    )
