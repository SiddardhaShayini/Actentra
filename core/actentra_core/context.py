"""Authorized execution context and postcondition binding for Actentra (Phase 5).

Binds:
- Action identity and parameters.
- Target resource.
- Authenticated principal.
- Executor identity.
- Approval identity.
- Policy version.
- Required postconditions.
- Expected result constraints.

Ensures callers cannot replace or weaken approved postconditions.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from actentra_core.canonicalize import (
    canonicalize_resource,
    canonicalize_unicode,
    hash_canonical,
)

_GENERIC_FORBIDDEN_CLAIMS: frozenset[str] = frozenset(
    {"verified", "ok", "success", "true", "any", "all", "none", "pass", "valid", ""}
)

_VALID_POSTCONDITION_CLAIMS: frozenset[str] = frozenset(
    {"digest_match", "absent", "exists", "table_exists", "row_count_match", "custom"}
)


class ContextError(ValueError):
    """Raised when an execution context or postcondition specification fails validation."""


def _canonicalize_value(val: Any) -> Any:
    if isinstance(val, dict):
        return {
            canonicalize_unicode(k).strip(): _canonicalize_value(v)
            for k, v in val.items()
        }
    if isinstance(val, (list, tuple)):
        return [_canonicalize_value(v) for v in val]
    if isinstance(val, str):
        return canonicalize_unicode(val)
    return val


def compute_content_digest(content: str | bytes) -> str:
    """Compute sha256:<hex> digest over raw bytes or utf-8 encoded string."""
    raw = content.encode("utf-8") if isinstance(content, str) else content
    digest = hashlib.sha256(raw).hexdigest()
    return f"sha256:{digest}"


@dataclass(frozen=True, slots=True)
class PostconditionSpec:
    """Specification of an expected postcondition that must be independently verified."""

    claim: str
    resource: str
    expected_digest: str | None = None
    strict: bool = True
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim,
            "resource": self.resource,
            "expected_digest": self.expected_digest,
            "strict": self.strict,
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PostconditionSpec:
        return cls(
            claim=canonicalize_unicode(str(data["claim"])).strip().lower(),
            resource=canonicalize_resource(str(data["resource"])),
            expected_digest=(
                str(data["expected_digest"]).strip().lower()
                if data.get("expected_digest")
                else None
            ),
            strict=bool(data.get("strict", True)),
            details=dict(data.get("details") or {}),
        )


def validate_postcondition_semantics(
    *,
    tool: str,
    verb: str,
    resource: str,
    claim: str,
    params: dict[str, Any] | None = None,
    expected_digest: str | None = None,
    strict: bool = False,
) -> PostconditionSpec:
    """Validate and enforce postcondition semantics for an operation.

    Rejects generic claims ('verified', 'ok', 'true', etc.).
    Under strict mode, rejects weak claims (e.g. 'exists' on a write operation).
    """
    clean_tool = canonicalize_unicode(tool).strip().lower()
    clean_verb = canonicalize_unicode(verb).strip().lower()
    clean_claim = canonicalize_unicode(claim).strip().lower()
    clean_res = canonicalize_resource(resource)

    if clean_claim in _GENERIC_FORBIDDEN_CLAIMS:
        raise ContextError(
            f"Generic postcondition claim {clean_claim!r} is not permitted; "
            f"expected a concrete semantic claim (e.g. 'digest_match', 'absent', 'exists')"
        )

    clean_params = params or {}

    # Strict rule 1: Write operations must verify content digest, not merely existence
    if strict and (clean_verb == "write" or clean_tool == "fs.write"):
        if clean_claim == "exists":
            raise ContextError(
                "Weak postcondition rejected: write operations under strict verification "
                "must verify content digest ('digest_match'), not merely file existence ('exists')"
            )
        if clean_claim not in ("digest_match", "custom"):
            raise ContextError(
                f"Invalid postcondition claim {clean_claim!r} for write operation; "
                f"expected 'digest_match'"
            )

    # Strict rule 2: Delete operations must verify resource absence
    if strict and (clean_verb == "delete" or clean_tool == "fs.delete") and clean_claim != "absent":
        raise ContextError(
            f"Invalid postcondition claim {clean_claim!r} for delete operation; "
            f"expected 'absent'"
        )

    # Derive expected digest from params['content'] if not explicitly passed
    final_digest = expected_digest
    if clean_claim == "digest_match" and final_digest is None and "content" in clean_params:
        content = clean_params["content"]
        if isinstance(content, (str, bytes)):
            final_digest = compute_content_digest(content)

    return PostconditionSpec(
        claim=clean_claim,
        resource=clean_res,
        expected_digest=final_digest,
        strict=strict,
    )


def compute_context_hash(
    *,
    crossing_id: str,
    tool: str,
    verb: str,
    resource: str,
    params: dict[str, Any],
    principal_id: str,
    executor_id: str,
    approval_id: str | None,
    policy_version: str,
    required_postconditions: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    expected_result_constraints: dict[str, Any],
) -> str:
    """Compute deterministic SHA-256 hash of the canonical execution context."""
    try:
        clean_res = canonicalize_resource(resource)
    except Exception:
        clean_res = canonicalize_unicode(resource).strip()

    payload = {
        "crossing_id": canonicalize_unicode(crossing_id).strip(),
        "tool": canonicalize_unicode(tool).strip().lower(),
        "verb": canonicalize_unicode(verb).strip().lower(),
        "resource": clean_res,
        "params": _canonicalize_value(params),
        "principal_id": canonicalize_unicode(principal_id).strip(),
        "executor_id": canonicalize_unicode(executor_id).strip(),
        "approval_id": (
            canonicalize_unicode(approval_id).strip() if approval_id is not None else None
        ),
        "policy_version": canonicalize_unicode(policy_version).strip(),
        "required_postconditions": [
            _canonicalize_value(p) for p in required_postconditions
        ],
        "expected_result_constraints": _canonicalize_value(expected_result_constraints),
    }
    return hash_canonical(payload)


@dataclass(frozen=True, slots=True)
class AuthorizedExecutionContext:
    """Immutable, cryptographically bound context for authorized execution."""

    crossing_id: str
    tool: str
    verb: str
    resource: str
    params: dict[str, Any]
    principal_id: str
    executor_id: str
    approval_id: str | None
    policy_version: str
    required_postconditions: tuple[dict[str, Any], ...]
    expected_result_constraints: dict[str, Any]
    context_hash: str = ""

    def verify_integrity(self) -> bool:
        """Verify that context_hash matches computed hash."""
        expected = compute_context_hash(
            crossing_id=self.crossing_id,
            tool=self.tool,
            verb=self.verb,
            resource=self.resource,
            params=self.params,
            principal_id=self.principal_id,
            executor_id=self.executor_id,
            approval_id=self.approval_id,
            policy_version=self.policy_version,
            required_postconditions=self.required_postconditions,
            expected_result_constraints=self.expected_result_constraints,
        )
        return self.context_hash == expected

    def to_dict(self) -> dict[str, Any]:
        return {
            "crossing_id": self.crossing_id,
            "tool": self.tool,
            "verb": self.verb,
            "resource": self.resource,
            "params": dict(self.params),
            "principal_id": self.principal_id,
            "executor_id": self.executor_id,
            "approval_id": self.approval_id,
            "policy_version": self.policy_version,
            "required_postconditions": list(self.required_postconditions),
            "expected_result_constraints": dict(self.expected_result_constraints),
            "context_hash": self.context_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthorizedExecutionContext:
        return cls(
            crossing_id=str(data["crossing_id"]),
            tool=str(data["tool"]),
            verb=str(data["verb"]),
            resource=str(data["resource"]),
            params=dict(data.get("params") or {}),
            principal_id=str(data["principal_id"]),
            executor_id=str(data["executor_id"]),
            approval_id=str(data["approval_id"]) if data.get("approval_id") else None,
            policy_version=str(data["policy_version"]),
            required_postconditions=tuple(data.get("required_postconditions") or ()),
            expected_result_constraints=dict(data.get("expected_result_constraints") or {}),
            context_hash=str(data.get("context_hash", "")),
        )


def build_execution_context(
    *,
    crossing_id: str,
    tool: str,
    verb: str,
    resource: str,
    params: dict[str, Any] | None = None,
    principal_id: str = "default-principal",
    executor_id: str = "default-executor",
    approval_id: str | None = None,
    policy_version: str = "1",
    required_postconditions: Sequence[PostconditionSpec | dict[str, Any]] | None = None,
    expected_result_constraints: dict[str, Any] | None = None,
) -> AuthorizedExecutionContext:
    """Validate, canonicalize, hash, and construct an AuthorizedExecutionContext."""
    clean_params = params or {}
    clean_res = canonicalize_resource(resource)
    clean_post: list[dict[str, Any]] = []
    if required_postconditions:
        for p in required_postconditions:
            if isinstance(p, PostconditionSpec):
                clean_post.append(p.to_dict())
            elif isinstance(p, dict):
                spec = PostconditionSpec.from_dict(p)
                clean_post.append(spec.to_dict())

    clean_constraints = expected_result_constraints or {}

    c_hash = compute_context_hash(
        crossing_id=crossing_id,
        tool=tool,
        verb=verb,
        resource=clean_res,
        params=clean_params,
        principal_id=principal_id,
        executor_id=executor_id,
        approval_id=approval_id,
        policy_version=policy_version,
        required_postconditions=clean_post,
        expected_result_constraints=clean_constraints,
    )

    return AuthorizedExecutionContext(
        crossing_id=crossing_id,
        tool=tool,
        verb=verb,
        resource=clean_res,
        params=clean_params,
        principal_id=principal_id,
        executor_id=executor_id,
        approval_id=approval_id,
        policy_version=policy_version,
        required_postconditions=tuple(clean_post),
        expected_result_constraints=clean_constraints,
        context_hash=c_hash,
    )
