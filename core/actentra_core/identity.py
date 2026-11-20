"""Explicit identity, trust boundaries, and authority model for Actentra (V5).

Provides a strict separation between:
- caller-supplied metadata (e.g. agent_id, session_id claimed by HTTP payload)
- authenticated operator identity (verified credentials, tokens, or local in-process callers)
- trust domains and delegated authority
"""

from __future__ import annotations

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
class CallerContext:
    """Authenticated caller context establishing trust boundaries."""

    principal_type: PrincipalType
    principal_id: str
    authenticated: bool
    trust_domain: str
    scopes: tuple[str, ...] = ()
    allowed_agents: tuple[str, ...] = ()
    delegated_by: str | None = None

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


def resolve_http_caller_context(
    *,
    headers: dict[str, str],
    expected_token: str | None = None,
    remote_addr: str = "127.0.0.1",
    token_principals: dict[str, CallerContext | dict[str, Any] | str] | None = None,
) -> CallerContext:
    """Resolve caller context from HTTP headers, verifying bearer token or principal mapping."""
    auth_header = headers.get("authorization", "").strip()
    client_identity = headers.get("x-actentra-identity", "").strip()
    delegated_by = headers.get("x-actentra-delegated-by", "").strip() or None

    if auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer ") :].strip()

        # 1. Configured token_principals mapping
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
                    allowed_agents=(mapped,) if not delegated_by else (mapped, delegated_by),
                    delegated_by=delegated_by,
                )
            elif isinstance(mapped, dict):
                p_type = PrincipalType(
                    mapped.get("principal_type", PrincipalType.AUTHENTICATED_AGENT)
                )
                p_id = mapped.get("principal_id", f"agent@{remote_addr}")
                allowed = mapped.get("allowed_agents")
                allowed_tuple = tuple(allowed) if allowed else (p_id,)
                ctx = CallerContext(
                    principal_type=p_type,
                    principal_id=p_id,
                    authenticated=bool(mapped.get("authenticated", True)),
                    trust_domain=mapped.get("trust_domain", "gateway_agent"),
                    scopes=tuple(mapped.get("scopes", DEFAULT_AGENT_SCOPES)),
                    allowed_agents=allowed_tuple,
                    delegated_by=mapped.get("delegated_by", delegated_by),
                )
            else:
                raise IdentitySecurityError(f"Invalid token principal mapping for token '{token}'")

            if client_identity and not ctx.is_agent_allowed(client_identity):
                raise IdentitySecurityError(
                    f"Conflicting identity claim: authenticated principal '{ctx.principal_id}' "
                    f"cannot assert identity '{client_identity}'"
                )
            return ctx

        # 2. Structured tokens: agent:<id>, operator:<id>, approver:<id>
        if token.startswith("agent:"):
            agent_name = token[len("agent:") :].strip()
            if not expected_token or token == expected_token or token_principals is None:
                allowed_tuple = (
                    (agent_name,) if not delegated_by else (agent_name, delegated_by)
                )
                ctx = CallerContext(
                    principal_type=PrincipalType.AUTHENTICATED_AGENT,
                    principal_id=agent_name,
                    authenticated=True,
                    trust_domain="gateway_agent",
                    scopes=DEFAULT_AGENT_SCOPES,
                    allowed_agents=allowed_tuple,
                    delegated_by=delegated_by,
                )
                if client_identity and not ctx.is_agent_allowed(client_identity):
                    raise IdentitySecurityError(
                        f"Conflicting identity claim: authenticated agent '{agent_name}' "
                        f"cannot assert identity '{client_identity}'"
                    )
                return ctx

        if token.startswith("approver:"):
            approver_name = token[len("approver:") :].strip()
            return CallerContext(
                principal_type=PrincipalType.HUMAN_APPROVER,
                principal_id=approver_name,
                authenticated=True,
                trust_domain="gateway_approver",
                scopes=DEFAULT_APPROVER_SCOPES,
                allowed_agents=(),
            )

        if token.startswith("operator:"):
            op_name = token[len("operator:") :].strip()
            return CallerContext(
                principal_type=PrincipalType.AUTHENTICATED_OPERATOR,
                principal_id=op_name,
                authenticated=True,
                trust_domain="gateway_operator",
                scopes=DEFAULT_OPERATOR_SCOPES,
                allowed_agents=("*",),
            )

        # 3. Expected shared operator token
        if expected_token and token == expected_token:
            return CallerContext(
                principal_type=PrincipalType.AUTHENTICATED_OPERATOR,
                principal_id=client_identity or f"token-operator@{remote_addr}",
                authenticated=True,
                trust_domain="gateway_operator",
                scopes=DEFAULT_OPERATOR_SCOPES,
                allowed_agents=("*",),
            )

    # In loopback mode without expected_token, classify as loopback caller
    if remote_addr in ("127.0.0.1", "::1", "localhost"):
        has_server_auth = bool(expected_token or token_principals)
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
