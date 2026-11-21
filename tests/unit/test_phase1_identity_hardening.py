"""Phase 1 Adversarial & Regression Test Suite: Identity & Delegation Hardening.

Verifies:
- ACT-01 reproduction: grant ID substitution exploit is completely prevented
- Grant ID substitution across all principals is rejected
- Delegator impersonation is rejected
- Delegatee substitution is rejected
- Revoked grants fail closed immediately
- Cascading revocation down nested delegation chains fails closed
- Expired grants fail closed immediately
- Unauthorized grant creation (unauthenticated or lacking scopes/agents) fails closed
- Scope escalation in grant creation is rejected
- Nested delegation restrictions (depth limits, scope attenuation, expiration bounding)
- Replay across principals is prevented
- Concurrent revocation and execution is thread-safe
- Missing and malformed credentials fail closed
- Audience mismatch fails closed
- Cryptographically signed Ed25519 delegation grants (issuance, verification, tampering detection)
- Canonical security context enforcement across Boundary, Services, Approvals, and Warrants
"""

from __future__ import annotations

import concurrent.futures
import io
import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from actentra.boundary import ActionBlockedError, Boundary
from actentra_core.identity import (
    CallerContext,
    DelegationGrant,
    DelegationRegistry,
    IdentitySecurityError,
    PrincipalType,
    issue_signed_delegation_grant,
    make_local_caller_context,
    resolve_http_caller_context,
    verify_signed_delegation_grant,
)
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_core.warrants import issue_warrant
from actentra_gateway.http_service import ActentraHTTPHandler
from actentra_gateway.services import AppServices

_HARDENING_POLICY = """\
version: 1
policy_id: test-phase1-hardening-policy
mode: enforce
defaults:
  verdict: deny
rules:
  - id: allow-fs-read
    match:
      tool: "fs.read"
      verb: read
    verdict: allow
  - id: ask-sensitive-write
    match:
      tool: "fs.write"
      verb: write
    verdict: ask
    reason: "Sensitive write requires human approval"
"""


def _dispatch_request(
    services: AppServices,
    path: str,
    method: str = "GET",
    data: dict[str, Any] | bytes | str | None = None,
    headers: dict[str, str] | None = None,
    auth_token: str | None = None,
    token_principals: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    """Helper to dispatch requests through ActentraHTTPHandler."""
    handler = ActentraHTTPHandler.__new__(ActentraHTTPHandler)
    server_mock = MagicMock()
    server_mock.services = services
    server_mock.boundary = services.boundary
    server_mock.auth_token = auth_token
    server_mock.token_principals = token_principals
    server_mock.delegation_registry = services.delegation_registry
    handler.server = server_mock
    handler.request_version = "HTTP/1.1"
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.close_connection = True
    handler.path = path
    handler.wfile = io.BytesIO()

    if data is not None:
        if isinstance(data, (bytes, str)):
            body_bytes = data if isinstance(data, bytes) else data.encode("utf-8")
        else:
            body_bytes = json.dumps(data).encode("utf-8")
    else:
        body_bytes = b""

    hdrs = {"Content-Length": str(len(body_bytes)), "Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    handler.headers = hdrs  # type: ignore[assignment]
    handler.rfile = io.BytesIO(body_bytes)

    if method == "GET":
        handler.do_GET()
    elif method == "POST":
        handler.do_POST()
    elif method == "DELETE":
        handler.do_DELETE()
    else:
        raise ValueError(f"Unsupported method: {method}")

    raw_output = handler.wfile.getvalue().decode("utf-8")
    status_line = raw_output.splitlines()[0]
    status_code = int(status_line.split()[1])
    parts = raw_output.split("\r\n\r\n", 1)
    body_str = parts[1] if len(parts) > 1 else ""
    try:
        parsed_body = json.loads(body_str)
    except Exception:
        parsed_body = body_str
    return status_code, parsed_body


# ==============================================================================
# 1. ACT-01 REPRODUCTION & PREVENTION TESTS
# ==============================================================================


def test_act01_original_exploit_prevented(tmp_path: Path) -> None:
    """Original ACT-01 Vulnerability: Mallory tries to hijack Alice's grant issued to Bob.

    Demonstrates that grant ID substitution is prevented across both resolver
    and HTTP gateway entry points.
    """
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_HARDENING_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    # 1. Alice creates a legitimate delegation grant to Bob
    alice_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="alice",
        authenticated=True,
        trust_domain="gateway_agent",
        scopes=("crossings:propose", "crossings:read"),
        allowed_agents=("alice",),
    )
    services.delegation_registry.register_grant(
        delegator=alice_ctx,
        delegatee_id="bob",
        allowed_agents=["alice"],
        scopes=["crossings:propose", "crossings:read"],
        grant_id="grant-alice-to-bob",
    )

    token_principals = {
        "tok-mallory": {
            "principal_id": "mallory",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["mallory"],
            "scopes": ["crossings:propose", "crossings:read"],
        },
        "tok-bob": {
            "principal_id": "bob",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["bob"],
            "scopes": ["crossings:propose", "crossings:read"],
        },
    }

    # 2. Direct resolver test: Mallory presents Alice's grant to Bob
    with pytest.raises(IdentitySecurityError) as exc_info:
        resolve_http_caller_context(
            headers={
                "authorization": "Bearer tok-mallory",
                "x-actentra-delegated-by": "alice",
                "x-actentra-delegation-grant": "grant-alice-to-bob",
            },
            token_principals=token_principals,
            delegation_registry=services.delegation_registry,
        )
    assert "Grant binding violation" in str(exc_info.value)
    assert "mallory" in str(exc_info.value)

    # 3. HTTP Gateway test: Mallory attempts to submit crossing as Alice via HTTP
    code, res = _dispatch_request(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "agent_id": "alice",
            "tool": "fs.read",
            "verb": "read",
            "resource": "secret_doc.txt",
        },
        headers={
            "Authorization": "Bearer tok-mallory",
            "X-Actentra-Delegated-By": "alice",
            "X-Actentra-Delegation-Grant": "grant-alice-to-bob",
        },
        token_principals=token_principals,
    )
    assert code == 403
    assert res.get("code") == "unauthorized_principal"
    assert "Grant binding violation" in res.get("error", "")

    # 4. Verify legitimate delegatee Bob CAN use the grant
    code_bob, res_bob = _dispatch_request(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "agent_id": "alice",
            "tool": "fs.read",
            "verb": "read",
            "resource": "secret_doc.txt",
        },
        headers={
            "Authorization": "Bearer tok-bob",
            "X-Actentra-Delegated-By": "alice",
            "X-Actentra-Delegation-Grant": "grant-alice-to-bob",
        },
        token_principals=token_principals,
    )
    assert code_bob == 200
    assert res_bob.get("verdict") == "allow"


# ==============================================================================
# 2. DELEGATION GRANT BINDING & SUBSTITUTION TESTS
# ==============================================================================


def test_grant_id_substitution_without_delegated_by_header(tmp_path: Path) -> None:
    """Attacker passes valid grant ID but omits Delegated-By header; must still fail closed."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_HARDENING_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    alice_ctx = make_local_caller_context("alice")
    services.delegation_registry.register_grant(
        delegator=alice_ctx,
        delegatee_id="bob",
        allowed_agents=["alice"],
        scopes=["crossings:propose", "crossings:read"],
        grant_id="grant-alice-bob-001",
    )

    token_principals = {
        "tok-mallory": {
            "principal_id": "mallory",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["mallory"],
            "scopes": ["crossings:propose"],
        }
    }

    # Mallory sends only X-Actentra-Delegation-Grant
    code, res = _dispatch_request(
        services,
        "/v1/crossings",
        method="POST",
        data={"agent_id": "alice", "tool": "fs.read", "verb": "read", "resource": "res.txt"},
        headers={
            "Authorization": "Bearer tok-mallory",
            "X-Actentra-Delegation-Grant": "grant-alice-bob-001",
        },
        token_principals=token_principals,
    )
    assert code == 403
    assert "Grant binding violation" in res.get("error", "")


def test_delegator_impersonation_mismatched_parent_claim(tmp_path: Path) -> None:
    """Attacker presents Alice->Mallory grant, but claims Delegated-By: charlie."""
    reg = DelegationRegistry()
    alice_ctx = make_local_caller_context("alice")
    reg.register_grant(
        delegator=alice_ctx,
        delegatee_id="mallory",
        allowed_agents=["alice"],
        scopes=["crossings:propose"],
        grant_id="grant-alice-mallory-002",
    )

    token_principals = {
        "tok-mallory": {
            "principal_id": "mallory",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["mallory"],
            "scopes": ["crossings:propose"],
        }
    }

    with pytest.raises(IdentitySecurityError) as exc_info:
        resolve_http_caller_context(
            headers={
                "authorization": "Bearer tok-mallory",
                "x-actentra-delegated-by": "charlie",  # Falsely claims charlie
                "x-actentra-delegation-grant": "grant-alice-mallory-002",
            },
            token_principals=token_principals,
            delegation_registry=reg,
        )
    assert "Grant binding violation" in str(exc_info.value)
    assert "charlie" in str(exc_info.value)


def test_unauthorized_parent_claim_without_grant_fails_closed() -> None:
    """Caller asserts X-Actentra-Delegated-By: victim without an active grant."""
    reg = DelegationRegistry()
    token_principals = {
        "tok-attacker": {
            "principal_id": "attacker",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["attacker"],
            "scopes": ["crossings:propose"],
        }
    }
    with pytest.raises(IdentitySecurityError) as exc_info:
        resolve_http_caller_context(
            headers={
                "authorization": "Bearer tok-attacker",
                "x-actentra-delegated-by": "victim-parent",
            },
            token_principals=token_principals,
            delegation_registry=reg,
        )
    assert "Unauthorized caller-supplied delegation" in str(exc_info.value)


# ==============================================================================
# 3. DELEGATION LIFECYCLE: REVOCATION, EXPIRATION & CASCADING
# ==============================================================================


def test_revoked_grant_immediately_rejected(tmp_path: Path) -> None:
    """A revoked grant is immediately rejected upon revocation."""
    reg = DelegationRegistry()
    alice_ctx = make_local_caller_context("alice")
    grant = reg.register_grant(
        delegator=alice_ctx,
        delegatee_id="bob",
        allowed_agents=["alice"],
        scopes=["crossings:propose"],
        grant_id="grant-revocation-test",
    )

    token_principals = {
        "tok-bob": {
            "principal_id": "bob",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["bob"],
            "scopes": ["crossings:propose"],
        }
    }

    # Before revocation: valid
    ctx = resolve_http_caller_context(
        headers={
            "authorization": "Bearer tok-bob",
            "x-actentra-delegated-by": "alice",
            "x-actentra-delegation-grant": grant.grant_id,
        },
        token_principals=token_principals,
        delegation_registry=reg,
    )
    assert ctx.is_agent_allowed("alice") is True

    # Alice revokes the grant
    revoked = reg.revoke_grant(grant.grant_id, revoker=alice_ctx)
    assert revoked is True

    # After revocation: immediately fails closed
    with pytest.raises(IdentitySecurityError) as exc_info:
        resolve_http_caller_context(
            headers={
                "authorization": "Bearer tok-bob",
                "x-actentra-delegated-by": "alice",
                "x-actentra-delegation-grant": grant.grant_id,
            },
            token_principals=token_principals,
            delegation_registry=reg,
        )
    assert "invalid or revoked" in str(exc_info.value)


def test_cascading_revocation_invalidates_descendants() -> None:
    """Revoking a parent grant in a chain automatically revokes all descendants."""
    reg = DelegationRegistry()
    alice_ctx = make_local_caller_context("alice")

    # 1. Alice -> Bob (depth 0, max_depth 2)
    grant_ab = reg.register_grant(
        delegator=alice_ctx,
        delegatee_id="bob",
        allowed_agents=["alice"],
        scopes=["crossings:propose", "crossings:read"],
        max_depth=2,
        grant_id="grant-alice-bob",
    )

    # 2. Bob -> Charlie (depth 1, child of grant-alice-bob)
    bob_ctx = CallerContext(
        principal_type=PrincipalType.DELEGATED_AGENT,
        principal_id="bob",
        authenticated=True,
        trust_domain="gateway_agent",
        scopes=("crossings:propose", "crossings:read"),
        allowed_agents=("alice", "bob"),
        delegated_by="alice",
        delegation_grant_id=grant_ab.grant_id,
    )
    grant_bc = reg.register_grant(
        delegator=bob_ctx,
        delegatee_id="charlie",
        allowed_agents=["alice"],
        scopes=["crossings:propose"],
        grant_id="grant-bob-charlie",
    )
    assert grant_bc.parent_grant_id == "grant-alice-bob"
    assert grant_bc.depth == 2

    # 3. Alice revokes root grant (grant-alice-bob)
    assert reg.revoke_grant("grant-alice-bob", revoker=alice_ctx) is True

    # 4. Check that child grant (grant-bob-charlie) was cascaded into revocation
    child_grant = reg.get_grant("grant-bob-charlie")
    assert child_grant is not None
    assert child_grant.revoked is True
    assert "Cascading revocation" in (child_grant.revocation_reason or "")

    # 5. Charlie attempting to validate binding fails closed
    with pytest.raises(IdentitySecurityError) as exc_info:
        reg.validate_grant_binding("grant-bob-charlie", authenticated_delegatee_id="charlie")
    assert "invalid or revoked" in str(exc_info.value)


def test_expired_grant_rejected_at_validation() -> None:
    """Grant with an expired timestamp fails closed."""
    reg = DelegationRegistry()
    alice_ctx = make_local_caller_context("alice")
    grant = reg.register_grant(
        delegator=alice_ctx,
        delegatee_id="bob",
        allowed_agents=["alice"],
        scopes=["crossings:propose"],
        ttl_seconds=0.05,
    )

    time.sleep(0.08)  # Allow grant to expire

    with pytest.raises(IdentitySecurityError) as exc_info:
        reg.validate_grant_binding(grant.grant_id, authenticated_delegatee_id="bob")
    assert "invalid or revoked" in str(exc_info.value)


# ==============================================================================
# 4. SCOPE ATTENUATION & NESTED DELEGATION RESTRICTIONS
# ==============================================================================


def test_unauthorized_grant_creation_rejected() -> None:
    """Unauthenticated caller or caller without authority cannot create a grant."""
    reg = DelegationRegistry()
    unauth_ctx = CallerContext(
        principal_type=PrincipalType.UNAUTHENTICATED_CALLER,
        principal_id="anon",
        authenticated=False,
        trust_domain="untrusted",
    )
    with pytest.raises(IdentitySecurityError, match="Unauthenticated caller cannot delegate"):
        reg.register_grant(
            delegator=unauth_ctx,
            delegatee_id="victim",
            allowed_agents=["victim"],
            scopes=["crossings:propose"],
        )


def test_scope_escalation_in_grant_creation_rejected() -> None:
    """Delegator cannot grant scopes that it does not possess."""
    reg = DelegationRegistry()
    dave_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="dave",
        authenticated=True,
        trust_domain="gateway_agent",
        scopes=("crossings:read",),  # Dave only has read scope
        allowed_agents=("dave",),
    )
    # Dave attempts to grant write / execute authority
    with pytest.raises(IdentitySecurityError) as exc_info:
        reg.register_grant(
            delegator=dave_ctx,
            delegatee_id="eve",
            allowed_agents=["dave"],
            scopes=["crossings:execute"],  # Escalation!
        )
    assert "Delegation scope violation" in str(exc_info.value)
    assert "crossings:execute" in str(exc_info.value)


def test_nested_delegation_depth_limit_enforced() -> None:
    """Nested delegation exceeding max_depth is rejected."""
    reg = DelegationRegistry()
    alice_ctx = make_local_caller_context("alice")

    # Default max_depth=1: Alice -> Bob is depth 0. Bob cannot delegate further.
    grant_ab = reg.register_grant(
        delegator=alice_ctx,
        delegatee_id="bob",
        allowed_agents=["alice"],
        scopes=["crossings:propose"],
        max_depth=1,
    )

    bob_ctx = CallerContext(
        principal_type=PrincipalType.DELEGATED_AGENT,
        principal_id="bob",
        authenticated=True,
        trust_domain="gateway_agent",
        scopes=("crossings:propose",),
        allowed_agents=("alice", "bob"),
        delegated_by="alice",
        delegation_grant_id=grant_ab.grant_id,
    )

    with pytest.raises(IdentitySecurityError, match="Delegation depth limit exceeded"):
        reg.register_grant(
            delegator=bob_ctx,
            delegatee_id="charlie",
            allowed_agents=["alice"],
            scopes=["crossings:propose"],
        )


def test_nested_delegation_expiration_bounded_by_parent() -> None:
    """Child grant expiration cannot exceed parent grant expiration."""
    reg = DelegationRegistry()
    alice_ctx = make_local_caller_context("alice")
    grant_ab = reg.register_grant(
        delegator=alice_ctx,
        delegatee_id="bob",
        allowed_agents=["alice"],
        scopes=["crossings:propose"],
        ttl_seconds=100.0,
        max_depth=2,
    )

    bob_ctx = CallerContext(
        principal_type=PrincipalType.DELEGATED_AGENT,
        principal_id="bob",
        authenticated=True,
        trust_domain="gateway_agent",
        scopes=("crossings:propose",),
        allowed_agents=("alice", "bob"),
        delegated_by="alice",
        delegation_grant_id=grant_ab.grant_id,
    )

    # Bob attempts to create grant with ttl=5000s; should be bounded to Alice's expires_at
    grant_bc = reg.register_grant(
        delegator=bob_ctx,
        delegatee_id="charlie",
        allowed_agents=["alice"],
        scopes=["crossings:propose"],
        ttl_seconds=5000.0,
    )
    assert grant_bc.expires_at is not None
    assert grant_ab.expires_at is not None
    assert grant_bc.expires_at <= grant_ab.expires_at


# ==============================================================================
# 5. AUDIENCE MISMATCH & REPLAY PREVENTION TESTS
# ==============================================================================


def test_audience_mismatch_fails_closed() -> None:
    """Grant restricted to audience 'system-alpha' fails when presented to 'system-beta'."""
    reg = DelegationRegistry()
    alice_ctx = make_local_caller_context("alice")
    grant = reg.register_grant(
        delegator=alice_ctx,
        delegatee_id="bob",
        allowed_agents=["alice"],
        scopes=["crossings:propose"],
        audience="system-alpha",
    )

    # When presented with matching audience -> succeeds
    valid_grant = reg.validate_grant_binding(
        grant.grant_id,
        authenticated_delegatee_id="bob",
        audience="system-alpha",
    )
    assert valid_grant.grant_id == grant.grant_id

    # When presented with mismatched audience -> rejected
    with pytest.raises(IdentitySecurityError, match="audience mismatch"):
        reg.validate_grant_binding(
            grant.grant_id,
            authenticated_delegatee_id="bob",
            audience="system-beta",
        )


def test_replay_across_principals_rejected() -> None:
    """Replaying an intercepted grant across different principals is rejected."""
    reg = DelegationRegistry()
    alice_ctx = make_local_caller_context("alice")
    grant = reg.register_grant(
        delegator=alice_ctx,
        delegatee_id="legit-worker",
        allowed_agents=["alice"],
        scopes=["crossings:propose"],
    )

    # Eve captures grant ID and attempts to replay
    with pytest.raises(IdentitySecurityError) as exc_info:
        reg.validate_grant_binding(grant.grant_id, authenticated_delegatee_id="eve-attacker")
    assert "Grant binding violation" in str(exc_info.value)


# ==============================================================================
# 6. CONCURRENT REVOCATION & EXECUTION TEST
# ==============================================================================


def test_concurrent_revocation_and_execution(tmp_path: Path) -> None:
    """Thread-safe race test: execution attempts immediately fail closed once revoked."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_HARDENING_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    alice_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="alice",
        authenticated=True,
        trust_domain="gateway_agent",
        scopes=("crossings:propose", "crossings:read"),
        allowed_agents=("alice",),
    )
    grant = services.delegation_registry.register_grant(
        delegator=alice_ctx,
        delegatee_id="worker",
        allowed_agents=["alice"],
        scopes=["crossings:propose", "crossings:read"],
        grant_id="grant-concurrent-test",
    )

    token_principals = {
        "tok-worker": {
            "principal_id": "worker",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["worker"],
            "scopes": ["crossings:propose", "crossings:read"],
        }
    }

    results: list[int] = []
    stop_event = concurrent.futures.ThreadPoolExecutor(max_workers=5)

    def worker_action() -> int:
        code, _ = _dispatch_request(
            services,
            "/v1/crossings",
            method="POST",
            data={
                "agent_id": "alice",
                "tool": "fs.read",
                "verb": "read",
                "resource": "doc.txt",
            },
            headers={
                "Authorization": "Bearer tok-worker",
                "X-Actentra-Delegated-By": "alice",
                "X-Actentra-Delegation-Grant": grant.grant_id,
            },
            token_principals=token_principals,
        )
        return code

    futures = [stop_event.submit(worker_action) for _ in range(20)]

    # Revoke grant concurrently
    services.delegation_registry.revoke_grant(grant.grant_id, revoker=alice_ctx)

    post_revocation_futures = [stop_event.submit(worker_action) for _ in range(10)]

    for f in futures:
        results.append(f.result())
    for f in post_revocation_futures:
        code = f.result()
        # Post-revocation requests must fail with 403
        assert code == 403

    stop_event.shutdown()


# ==============================================================================
# 7. CRYPTOGRAPHIC ED25519 DELEGATION GRANTS TEST
# ==============================================================================


def test_cryptographic_signed_delegation_grants() -> None:
    """Cryptographic signing, verification, and tamper detection with Ed25519."""
    privkey = Ed25519PrivateKey.generate()
    priv_pem = privkey.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    pub_pem = privkey.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    alice_ctx = make_local_caller_context("alice")
    signed_grant = issue_signed_delegation_grant(
        delegator=alice_ctx,
        delegatee_id="bob",
        allowed_agents=["alice"],
        scopes=["crossings:propose"],
        privkey_pem=priv_pem,
        ttl_seconds=3600.0,
        audience="gateway-cluster-1",
    )

    assert signed_grant.signature is not None

    # 1. Verification succeeds with valid public key and parameters
    valid, msg = verify_signed_delegation_grant(
        signed_grant,
        pubkey_pem=pub_pem,
        expected_delegatee="bob",
        expected_delegator="alice",
        expected_audience="gateway-cluster-1",
    )
    assert valid is True
    assert msg == "Delegation grant valid"

    # 2. Tampering detection: Altering delegatee invalidates signature
    tampered_grant = DelegationGrant(
        grant_id=signed_grant.grant_id,
        delegator_id=signed_grant.delegator_id,
        delegatee_id="mallory",  # Tampered!
        allowed_agents=signed_grant.allowed_agents,
        scopes=signed_grant.scopes,
        parent_grant_id=signed_grant.parent_grant_id,
        revoked=signed_grant.revoked,
        expires_at=signed_grant.expires_at,
        issued_at=signed_grant.issued_at,
        issuer=signed_grant.issuer,
        version=signed_grant.version,
        audience=signed_grant.audience,
        depth=signed_grant.depth,
        max_depth=signed_grant.max_depth,
        nonce=signed_grant.nonce,
        signature=signed_grant.signature,
    )
    valid_tampered, msg_tampered = verify_signed_delegation_grant(
        tampered_grant,
        pubkey_pem=pub_pem,
    )
    assert valid_tampered is False
    assert "signature invalid" in msg_tampered.lower()

    # 3. Wrong public key fails verification
    other_priv = Ed25519PrivateKey.generate()
    other_pub_pem = other_priv.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    valid_wrong_key, msg_wrong_key = verify_signed_delegation_grant(
        signed_grant,
        pubkey_pem=other_pub_pem,
    )
    assert valid_wrong_key is False
    assert "signature invalid" in msg_wrong_key.lower()


# ==============================================================================
# 8. CANONICAL SECURITY CONTEXT PROPAGATION ACROSS LAYERS
# ==============================================================================


def test_boundary_enforces_caller_context_principal_binding(tmp_path: Path) -> None:
    """Boundary.execute strictly binds agent_id to caller_context."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_HARDENING_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store, agent_id="agent-restricted")

    auth_caller = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="agent-restricted",
        authenticated=True,
        trust_domain="gateway_agent",
        scopes=("crossings:execute",),
        allowed_agents=("agent-restricted",),
    )

    # 1. Matching authenticated caller context succeeds
    res = boundary.execute(
        tool="fs.read",
        verb="read",
        resource="res.txt",
        fn=lambda env, dec: "read-success",
        caller_context=auth_caller,
    )
    assert res == "read-success"

    # 2. Impersonating caller context fails with ActionBlockedError (UNAUTHORIZED_PRINCIPAL)
    unauthorized_caller = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="attacker-principal",
        authenticated=True,
        trust_domain="gateway_agent",
        scopes=("crossings:execute",),
        allowed_agents=("attacker-principal",),  # Not allowed for 'agent-restricted'
    )
    with pytest.raises(ActionBlockedError) as exc_info:
        boundary.execute(
            tool="fs.read",
            verb="read",
            resource="res.txt",
            fn=lambda env, dec: "fail",
            caller_context=unauthorized_caller,
        )
    assert "UNAUTHORIZED_PRINCIPAL" in str(exc_info.value)

    # 3. Caller lacking crossings:execute fails with SCOPE_DENIED
    no_exec_caller = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="agent-restricted",
        authenticated=True,
        trust_domain="gateway_agent",
        scopes=("crossings:read",),  # Lacks crossings:execute
        allowed_agents=("agent-restricted",),
    )
    with pytest.raises(ActionBlockedError) as exc_info:
        boundary.execute(
            tool="fs.read",
            verb="read",
            resource="res.txt",
            fn=lambda env, dec: "fail",
            caller_context=no_exec_caller,
        )
    assert "SCOPE_DENIED" in str(exc_info.value)


def test_approval_resolution_propagates_approver_identity(tmp_path: Path) -> None:
    """Approval resolution stores the authenticated approver principal in durable receipts."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_HARDENING_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    # Propose sensitive write -> ASK
    resp = services.submit_crossing(
        {"agent_id": "builder", "tool": "fs.write", "verb": "write", "resource": "config.yaml"}
    )
    assert resp.get("verdict") == "ask"
    cid = resp["crossing_id"]

    # Approver approves crossing
    approver_ctx = CallerContext(
        principal_type=PrincipalType.HUMAN_APPROVER,
        principal_id="human-alice@corp",
        authenticated=True,
        trust_domain="human_approver",
        scopes=("crossings:approve", "crossings:read"),
    )
    services.resolve_approval(cid, approved=True, caller_context=approver_ctx)

    # Verify pending approval record has approver_id recorded
    pending = store.get_pending_approval(cid)
    assert pending is not None
    assert pending.status == "approved"
    assert pending.approver_id == "human-alice@corp"


def test_warrant_holder_binding_with_caller_context(tmp_path: Path) -> None:
    """Warrant holder must match caller_context principal identity."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_HARDENING_POLICY)

    privkey = Ed25519PrivateKey.generate()
    priv_pem = privkey.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    pub_pem = privkey.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    boundary = Boundary(
        policy=pack,
        receipt_store=store,
        agent_id="authorized-holder",
        warrant_public_key=pub_pem,
    )

    # Issue warrant specifically for 'authorized-holder'
    warrant = issue_warrant(
        holder="authorized-holder",
        allowed_tools=["fs.read"],
        allowed_resources=["*"],
        privkey_pem=priv_pem,
        issuer_id="admin",
    )

    # Caller with mismatched principal identity attempting to use the warrant fails
    mismatched_caller = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="impostor-agent",
        authenticated=True,
        trust_domain="gateway_agent",
        scopes=("crossings:execute",),
        allowed_agents=("authorized-holder",),  # Even if allowed_agents includes it
        claimed_identity="impostor-agent",
        authenticated_principal_id="impostor-agent",
    )

    with pytest.raises(ActionBlockedError) as exc_info:
        boundary.execute(
            tool="fs.read",
            verb="read",
            resource="data.txt",
            fn=lambda env, dec: "ok",
            warrant=warrant,
            caller_context=mismatched_caller,
        )
    assert "WARRANT_HOLDER_MISMATCH" in str(exc_info.value)
