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
    UNAUTHENTICATED_CALLER = "unauthenticated_caller"
    DELEGATED_AGENT = "delegated_agent"


_RESERVED_SYSTEM_IDENTIFIERS = frozenset(
    {"system", "kernel", "admin", "root", "actentra_internal", "policy_kernel"}
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

    @property
    def is_trusted_operator(self) -> bool:
        """True if the caller is an authenticated operator or local process."""
        return self.authenticated and self.principal_type in (
            PrincipalType.LOCAL_PROCESS,
            PrincipalType.AUTHENTICATED_OPERATOR,
        )

    def validate_identity_claims(
        self,
        claimed_agent_id: str,
        claimed_provenance_trust: str | None = None,
    ) -> None:
        """Validate that caller is permitted to assert the claimed identity and trust."""
        clean_agent = canonicalize_unicode(claimed_agent_id).strip().lower()
        if not self.is_trusted_operator:
            # Unauthenticated or non-operator caller cannot impersonate system/admin identities
            if clean_agent in _RESERVED_SYSTEM_IDENTIFIERS:
                raise IdentitySecurityError(
                    f"Unauthenticated caller '{self.principal_id}' cannot "
                    f"claim reserved system identity '{claimed_agent_id}'"
                )
            # Unauthenticated caller cannot assert 'trusted' provenance directly
            if claimed_provenance_trust == "trusted":
                raise IdentitySecurityError(
                    f"Caller '{self.principal_id}' is not an authenticated operator "
                    "and cannot assert trust='trusted'"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_type": self.principal_type.value,
            "principal_id": self.principal_id,
            "authenticated": self.authenticated,
            "trust_domain": self.trust_domain,
            "scopes": list(self.scopes),
        }


def make_local_caller_context(principal_id: str = "local_operator") -> CallerContext:
    """Create trusted caller context for in-process SDK execution."""
    return CallerContext(
        principal_type=PrincipalType.LOCAL_PROCESS,
        principal_id=principal_id,
        authenticated=True,
        trust_domain="local_boundary",
        scopes=("*",),
    )


def resolve_http_caller_context(
    *,
    headers: dict[str, str],
    expected_token: str | None = None,
    remote_addr: str = "127.0.0.1",
) -> CallerContext:
    """Resolve caller context from HTTP headers, verifying bearer token if configured."""
    auth_header = headers.get("authorization", "").strip()
    client_identity = headers.get("x-actentra-identity", "").strip()

    if expected_token and auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer ") :].strip()
        if token == expected_token:
            return CallerContext(
                principal_type=PrincipalType.AUTHENTICATED_OPERATOR,
                principal_id=client_identity or f"token-operator@{remote_addr}",
                authenticated=True,
                trust_domain="gateway_operator",
                scopes=("*",),
            )

    # In loopback mode without expected_token, still classify as loopback caller
    if remote_addr in ("127.0.0.1", "::1", "localhost"):
        return CallerContext(
            principal_type=PrincipalType.UNAUTHENTICATED_CALLER,
            principal_id=client_identity or f"loopback@{remote_addr}",
            authenticated=False,
            trust_domain="local_loopback",
            scopes=("crossings:propose", "crossings:read"),
        )

    return CallerContext(
        principal_type=PrincipalType.UNAUTHENTICATED_CALLER,
        principal_id=client_identity or f"anonymous@{remote_addr}",
        authenticated=False,
        trust_domain="untrusted_network",
        scopes=(),
    )
