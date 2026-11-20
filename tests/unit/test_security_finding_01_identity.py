"""Security regression tests for Finding 01: Caller-asserted agent identity and delegation.

Verifies:
- Caller identity spoofing in crossings is rejected (HTTP 403 / unauthorized_principal)
- Header identity manipulation (X-Actentra-Identity) is rejected or strictly reconciled
- Untrusted caller headers cannot grant operator or human approver roles
- Unauthorized handoff advancement and verification attempts are rejected
- Legitimate delegated authority succeeds
- Missing or unauthorized owner_agent_id on lease releases is rejected and fails closed
- Unauthorized lease acquisitions are rejected
- Privilege escalation on approvals and freeze/unfreeze endpoints is blocked
- Concurrent requests across threads preserve principal isolation
"""

from __future__ import annotations

import concurrent.futures
import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from actentra.boundary import Boundary
from actentra_core.identity import (
    CallerContext,
    IdentitySecurityError,
    PrincipalType,
    resolve_http_caller_context,
)
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_gateway.http_service import ActentraHTTPHandler
from actentra_gateway.services import AppServices, ExecutorRegistry

_SECURITY_TEST_POLICY = """\
version: 1
policy_id: security-finding-01-policy
mode: enforce
defaults:
  verdict: deny
rules:
  - id: allow-agent-read
    match:
      tool: "fs.read"
      verb: read
    verdict: allow
  - id: ask-admin-deploy
    match:
      tool: "deploy"
      verb: write
    verdict: ask
    reason: "Production deployment requires authorized human approval"
"""


def _dispatch(
    services: AppServices,
    path: str,
    method: str = "GET",
    data: dict[str, Any] | bytes | str | None = None,
    headers: dict[str, str] | None = None,
    auth_token: str | None = None,
    token_principals: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    """Helper to dispatch HTTP requests through ActentraHTTPHandler with optional auth tokens."""
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
    elif method == "OPTIONS":
        handler.do_OPTIONS()
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


def test_crossing_identity_spoofing_rejected(tmp_path: Path) -> None:
    """Authenticated caller cannot assert a different agent identity in crossings."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    token_principals = {
        "token-attacker": {
            "principal_id": "attacker-agent",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["attacker-agent"],
            "scopes": ["crossings:propose", "crossings:read"],
        },
        "token-victim": {
            "principal_id": "victim-agent",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["victim-agent"],
            "scopes": ["crossings:propose", "crossings:read"],
        },
    }

    # 1. Attacker attempts to submit crossing claiming to be 'victim-agent'
    code, res = _dispatch(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "fs.read",
            "verb": "read",
            "resource": "resource:secret",
            "agent_id": "victim-agent",
        },
        headers={"Authorization": "Bearer token-attacker"},
        token_principals=token_principals,
    )
    assert code == 403
    assert res.get("code") == "unauthorized_principal"
    assert "not authorized to assert identity" in res.get("error", "")

    # 2. Attacker using structured token 'agent:attacker-agent' claiming 'victim-agent'
    code, res = _dispatch(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "fs.read",
            "verb": "read",
            "resource": "resource:secret",
            "agent_id": "victim-agent",
        },
        headers={"Authorization": "Bearer agent:attacker-agent"},
    )
    assert code == 403
    assert res.get("code") == "unauthorized_principal"

    # 3. Attacker submits with their own legitimate identity
    code, res = _dispatch(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "fs.read",
            "verb": "read",
            "resource": "resource:secret",
            "agent_id": "attacker-agent",
        },
        headers={"Authorization": "Bearer token-attacker"},
        token_principals=token_principals,
    )
    assert code == 200
    assert res.get("verdict") == "allow"

    # 4. If agent_id is omitted by authenticated agent, it binds automatically to caller principal
    code, res = _dispatch(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "fs.read",
            "verb": "read",
            "resource": "resource:secret",
        },
        headers={"Authorization": "Bearer token-attacker"},
        token_principals=token_principals,
    )
    assert code == 200
    # Check receipt was stored under authenticated agent
    env = store.get_envelope(res["crossing_id"])
    assert env is not None
    assert env["agent"]["id"] == "attacker-agent"


def test_header_identity_spoofing_rejected(tmp_path: Path) -> None:
    """X-Actentra-Identity headers conflicting with authenticated token are rejected."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    token_principals = {
        "token-attacker": {
            "principal_id": "attacker-agent",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["attacker-agent"],
            "scopes": ["crossings:propose"],
        }
    }

    # Attacker passes valid token for attacker, but adds header asserting victim
    code, res = _dispatch(
        services,
        "/v1/crossings",
        method="POST",
        data={"tool": "fs.read", "verb": "read", "resource": "resource:test"},
        headers={
            "Authorization": "Bearer token-attacker",
            "X-Actentra-Identity": "victim-agent",
        },
        token_principals=token_principals,
    )
    assert code == 403
    assert res.get("code") == "unauthorized_principal"
    assert "cannot assert identity 'victim-agent'" in res.get("error", "")


def test_operator_privilege_spoofing_via_headers_rejected() -> None:
    """Untrusted callers cannot gain operator or approver roles via client headers."""
    # 1. Unauthenticated remote caller asserting operator/approver headers
    ctx_remote = resolve_http_caller_context(
        headers={
            "x-actentra-trust-domain": "trusted_operator",
            "x-actentra-principal-type": "human_approver",
        },
        remote_addr="192.168.1.100",
    )
    assert ctx_remote.authenticated is False
    assert ctx_remote.is_trusted_operator is False
    assert ctx_remote.is_approver is False
    assert ctx_remote.trust_domain == "untrusted_network"

    # 2. Authenticated agent caller asserting elevated headers
    ctx_agent = resolve_http_caller_context(
        headers={
            "authorization": "Bearer agent:regular-bot",
            "x-actentra-trust-domain": "trusted_operator",
            "x-actentra-principal-type": "human_approver",
        },
        remote_addr="127.0.0.1",
    )
    assert ctx_agent.authenticated is True
    assert ctx_agent.principal_type == PrincipalType.AUTHENTICATED_AGENT
    assert ctx_agent.is_trusted_operator is False
    assert ctx_agent.is_approver is False

    # 3. When server authentication is enabled, unauthenticated loopback caller lacks approver role
    ctx_loopback_with_auth = resolve_http_caller_context(
        headers={
            "x-actentra-trust-domain": "trusted_operator",
            "x-actentra-principal-type": "human_approver",
        },
        expected_token="gateway-secret-token",
        remote_addr="127.0.0.1",
    )
    assert ctx_loopback_with_auth.authenticated is False
    assert ctx_loopback_with_auth.is_approver is False
    assert ctx_loopback_with_auth.is_trusted_operator is False


def test_unauthorized_handoff_advance_rejected(tmp_path: Path) -> None:
    """Only the assigned agent or authorized delegate can advance a task handoff."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    token_principals = {
        "tok-builder": {
            "principal_id": "agent-builder",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["agent-builder"],
            "scopes": ["handoffs:advance", "handoffs:create"],
        },
        "tok-attacker": {
            "principal_id": "agent-attacker",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["agent-attacker"],
            "scopes": ["handoffs:advance"],
        },
    }

    # Create handoff initiated and assigned to agent-builder
    code, created = _dispatch(
        services,
        "/v1/handoffs",
        method="POST",
        data={
            "task_id": "task-secure-01",
            "initiator_agent_id": "agent-builder",
            "assigned_agent_id": "agent-builder",
            "verifier_agent_id": "agent-auditor",
            "allowed_verbs": ["read", "write"],
        },
        headers={"Authorization": "Bearer tok-builder"},
        token_principals=token_principals,
    )
    assert code == 201
    handoff_id = created["handoff_id"]

    # Attacker attempts to advance handoff by claiming caller_agent_id='agent-builder'
    code, res = _dispatch(
        services,
        f"/v1/handoffs/{handoff_id}/advance",
        method="POST",
        data={
            "caller_agent_id": "agent-builder",
            "next_agent_id": "agent-auditor",
        },
        headers={"Authorization": "Bearer tok-attacker"},
        token_principals=token_principals,
    )
    assert code == 403
    assert "cannot advance handoff as 'agent-builder'" in res.get("error", "")

    # Attacker attempts to advance handoff with their own identity
    code, res = _dispatch(
        services,
        f"/v1/handoffs/{handoff_id}/advance",
        method="POST",
        data={
            "caller_agent_id": "agent-attacker",
            "next_agent_id": "agent-auditor",
        },
        headers={"Authorization": "Bearer tok-attacker"},
        token_principals=token_principals,
    )
    assert code == 403
    assert "is not authorized for handoff" in res.get("error", "")

    # Legitimate builder advances handoff
    code, res = _dispatch(
        services,
        f"/v1/handoffs/{handoff_id}/advance",
        method="POST",
        data={
            "caller_agent_id": "agent-builder",
            "next_agent_id": "agent-auditor",
        },
        headers={"Authorization": "Bearer tok-builder"},
        token_principals=token_principals,
    )
    assert code == 200
    assert res["status"] == "active"
    assert res["assigned_agent_id"] == "agent-auditor"


def test_unauthorized_handoff_verify_rejected(tmp_path: Path) -> None:
    """Only designated verifier agent can verify a task handoff."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "verified.txt").write_text("ok", encoding="utf-8")
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    reg = ExecutorRegistry()
    reg.register_fs(ws)
    services = AppServices(boundary, executor_registry=reg)

    token_principals = {
        "tok-builder": {
            "principal_id": "agent-builder",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["agent-builder"],
            "scopes": ["handoffs:advance", "handoffs:create"],
        },
        "tok-auditor": {
            "principal_id": "agent-auditor",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["agent-auditor"],
            "scopes": ["handoffs:verify"],
        },
        "tok-attacker": {
            "principal_id": "agent-attacker",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["agent-attacker"],
            "scopes": ["handoffs:verify"],
        },
    }

    # 1. Create handoff
    code, created = _dispatch(
        services,
        "/v1/handoffs",
        method="POST",
        data={
            "task_id": "task-verify-01",
            "initiator_agent_id": "agent-builder",
            "assigned_agent_id": "agent-builder",
            "verifier_agent_id": "agent-auditor",
            "allowed_verbs": ["read"],
            "assertions": {"path:verified.txt": "exists"},
        },
        headers={"Authorization": "Bearer tok-builder"},
        token_principals=token_principals,
    )
    assert code == 201
    hid = created["handoff_id"]

    # 2. Attacker attempts to verify handoff claiming verifier_agent_id='agent-auditor'
    code, res = _dispatch(
        services,
        f"/v1/handoffs/{hid}/verify",
        method="POST",
        data={"verifier_agent_id": "agent-auditor"},
        headers={"Authorization": "Bearer tok-attacker"},
        token_principals=token_principals,
    )
    assert code == 403
    assert "cannot verify handoff as 'agent-auditor'" in res.get("error", "")

    # 3. Attacker attempts to verify with their own identity
    code, res = _dispatch(
        services,
        f"/v1/handoffs/{hid}/verify",
        method="POST",
        data={"verifier_agent_id": "agent-attacker"},
        headers={"Authorization": "Bearer tok-attacker"},
        token_principals=token_principals,
    )
    assert code == 403
    assert "is not the designated verifier" in res.get("error", "")

    # 4. Legitimate auditor verifies
    code, res = _dispatch(
        services,
        f"/v1/handoffs/{hid}/verify",
        method="POST",
        data={"verifier_agent_id": "agent-auditor"},
        headers={"Authorization": "Bearer tok-auditor"},
        token_principals=token_principals,
    )
    assert code == 200
    assert res["status"] == "completed"


def test_delegated_authority_succeeds(tmp_path: Path) -> None:
    """Subagents with explicit delegation can advance handoffs on behalf of assigned agent."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    # Worker has explicit delegation from agent-builder
    token_principals = {
        "tok-subagent": {
            "principal_id": "subagent-worker-1",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["subagent-worker-1", "agent-builder"],
            "delegated_by": "agent-builder",
            "scopes": ["handoffs:advance"],
        }
    }

    # Direct services handoff creation
    handoff = services.create_task_handoff(
        task_id="task-delegated-01",
        initiator_agent_id="agent-planner",
        assigned_agent_id="agent-builder",
        verifier_agent_id="agent-auditor",
        allowed_verbs=["read", "write"],
    )
    hid = handoff["handoff_id"]

    # Delegated subagent advances handoff on behalf of agent-builder
    code, res = _dispatch(
        services,
        f"/v1/handoffs/{hid}/advance",
        method="POST",
        data={
            "caller_agent_id": "agent-builder",
            "next_agent_id": "agent-auditor",
            "output_artifacts": ["delegated-work.txt"],
        },
        headers={"Authorization": "Bearer tok-subagent"},
        token_principals=token_principals,
    )
    assert code == 200
    assert res["status"] == "active"
    assert res["assigned_agent_id"] == "agent-auditor"

    # But delegated worker cannot advance handoffs assigned to another un-delegated agent
    handoff_other = services.create_task_handoff(
        task_id="task-other-01",
        initiator_agent_id="agent-planner",
        assigned_agent_id="other-agent",
        verifier_agent_id="agent-auditor",
        allowed_verbs=["read"],
    )
    code, res = _dispatch(
        services,
        f"/v1/handoffs/{handoff_other['handoff_id']}/advance",
        method="POST",
        data={"caller_agent_id": "other-agent", "next_agent_id": "agent-auditor"},
        headers={"Authorization": "Bearer tok-subagent"},
        token_principals=token_principals,
    )
    assert code == 403
    assert "cannot advance handoff as 'other-agent'" in res.get("error", "")


def test_unauthorized_lease_release_and_missing_owner_rejected(tmp_path: Path) -> None:
    """Resource leases cannot be released without authenticated and matching owner_agent_id."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    token_principals = {
        "tok-owner": {
            "principal_id": "agent-owner",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["agent-owner"],
            "scopes": ["leases:acquire", "leases:release"],
        },
        "tok-attacker": {
            "principal_id": "agent-attacker",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["agent-attacker"],
            "scopes": ["leases:acquire", "leases:release"],
        },
    }

    # 1. Acquire lease under agent-owner
    code, lease = _dispatch(
        services,
        "/v1/leases",
        method="POST",
        data={
            "resource": "db:production-users",
            "owner_agent_id": "agent-owner",
            "session_id": "s-lease",
        },
        headers={"Authorization": "Bearer tok-owner"},
        token_principals=token_principals,
    )
    assert code == 201
    lid = lease["lease"]["lease_id"]

    # 2. Attacker attempts to release without specifying owner_agent_id in body
    code, res = _dispatch(
        services,
        f"/v1/leases/{lid}/release",
        method="POST",
        data={},
        headers={"Authorization": "Bearer tok-attacker"},
        token_principals=token_principals,
    )
    assert code == 400
    assert "owner_agent_id" in res.get("error", "")

    # Lease must still be active
    active = services.get_resource_lease(lid)
    assert active is not None
    assert active["status"] == "active"

    # 3. Direct store check: calling release_lease with None or whitespace fails closed
    assert store.release_lease(lid, owner_agent_id=None) is False  # type: ignore[arg-type]
    assert store.release_lease(lid, owner_agent_id="   ") is False

    # 4. Attacker attempts to release asserting caller is owner-agent
    code, res = _dispatch(
        services,
        f"/v1/leases/{lid}/release",
        method="POST",
        data={"owner_agent_id": "agent-owner"},
        headers={"Authorization": "Bearer tok-attacker"},
        token_principals=token_principals,
    )
    assert code == 403
    assert "cannot release lease owned by 'agent-owner'" in res.get("error", "")

    # Lease must still be active
    active = services.get_resource_lease(lid)
    assert active is not None
    assert active["status"] == "active"

    # 5. Legitimate owner releases the lease
    code, res = _dispatch(
        services,
        f"/v1/leases/{lid}/release",
        method="POST",
        data={"owner_agent_id": "agent-owner"},
        headers={"Authorization": "Bearer tok-owner"},
        token_principals=token_principals,
    )
    assert code == 200
    assert res["released"] is True


def test_unauthorized_lease_acquisition_rejected(tmp_path: Path) -> None:
    """Authenticated caller cannot acquire leases under a victim's agent ID."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    token_principals = {
        "tok-attacker": {
            "principal_id": "agent-attacker",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["agent-attacker"],
            "scopes": ["leases:acquire"],
        }
    }

    code, res = _dispatch(
        services,
        "/v1/leases",
        method="POST",
        data={
            "resource": "db:customers",
            "owner_agent_id": "agent-victim",
            "session_id": "s-lease",
        },
        headers={"Authorization": "Bearer tok-attacker"},
        token_principals=token_principals,
    )
    assert code == 403
    assert res.get("code") == "unauthorized_principal"
    assert "cannot acquire lease as 'agent-victim'" in res.get("error", "")


def test_privilege_escalation_approvals_and_freeze_rejected(tmp_path: Path) -> None:
    """Normal agents cannot approve crossings or call freeze/unfreeze endpoints."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    token_principals = {
        "tok-agent": {
            "principal_id": "agent-regular",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["agent-regular"],
            "scopes": ["crossings:propose", "crossings:read"],
        },
        "tok-approver": {
            "principal_id": "approver-alice",
            "principal_type": "human_approver",
            "scopes": ["crossings:approve", "crossings:read"],
        },
        "tok-operator": {
            "principal_id": "operator-root",
            "principal_type": "authenticated_operator",
            "scopes": ["admin:freeze", "admin:unfreeze", "crossings:approve", "*"],
        },
    }

    # 1. Create a crossing requiring approval (ASK verdict)
    code, crossing = _dispatch(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "deploy",
            "verb": "write",
            "resource": "cluster:prod",
            "agent_id": "agent-regular",
        },
        headers={"Authorization": "Bearer tok-agent"},
        token_principals=token_principals,
    )
    assert code == 200
    assert crossing["verdict"] == "ask"
    cid = crossing["crossing_id"]

    # 2. Agent attempts to approve the crossing
    code, res = _dispatch(
        services,
        f"/v1/crossings/{cid}/approve",
        method="POST",
        data={"approved": True, "approver_notes": "self-approved"},
        headers={"Authorization": "Bearer tok-agent"},
        token_principals=token_principals,
    )
    assert code == 403
    assert "not authorized to resolve approvals" in res.get("error", "")

    # 3. Agent attempts to call /v1/freeze
    code, res = _dispatch(
        services,
        "/v1/freeze",
        method="POST",
        headers={"Authorization": "Bearer tok-agent"},
        token_principals=token_principals,
    )
    assert code == 403
    assert "Only trusted operators may freeze" in res.get("error", "")

    # 4. Human approver approves the crossing
    code, res = _dispatch(
        services,
        f"/v1/crossings/{cid}/approve",
        method="POST",
        data={"approved": True, "approver_notes": "verified by human security review"},
        headers={"Authorization": "Bearer tok-approver"},
        token_principals=token_principals,
    )
    assert code == 200
    assert res["status"] == "approved"

    # 5. Operator freezes the gateway
    code, res = _dispatch(
        services,
        "/v1/freeze",
        method="POST",
        headers={"Authorization": "Bearer tok-operator"},
        token_principals=token_principals,
    )
    assert code == 200
    assert res["frozen"] is True
    assert boundary.engine.frozen is True

    # 6. Agent cannot unfreeze
    code, res = _dispatch(
        services,
        "/v1/unfreeze",
        method="POST",
        headers={"Authorization": "Bearer tok-agent"},
        token_principals=token_principals,
    )
    assert code == 403
    assert boundary.engine.frozen is True

    # 7. Operator unfreezes
    code, res = _dispatch(
        services,
        "/v1/unfreeze",
        method="POST",
        headers={"Authorization": "Bearer tok-operator"},
        token_principals=token_principals,
    )
    assert code == 200
    assert res["frozen"] is False
    assert boundary.engine.frozen is False


def test_concurrent_requests_preserve_identity_isolation(tmp_path: Path) -> None:
    """Verify that concurrent requests across threads do not leak caller identities."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    token_principals = {
        f"tok-{i}": {
            "principal_id": f"agent-{i}",
            "principal_type": "authenticated_agent",
            "allowed_agents": [f"agent-{i}"],
            "scopes": ["crossings:propose", "crossings:read"],
        }
        for i in range(10)
    }

    results: list[tuple[int, dict[str, Any], int]] = []

    def _worker(worker_id: int) -> tuple[int, dict[str, Any], int]:
        # Odd workers make legitimate requests with matching agent_id
        # Even workers attempt to forge identity of worker 99
        if worker_id % 2 == 1:
            claimed_agent = f"agent-{worker_id}"
            expected_code = 200
        else:
            claimed_agent = "agent-99"
            expected_code = 403

        code, body = _dispatch(
            services,
            "/v1/crossings",
            method="POST",
            data={
                "tool": "fs.read",
                "verb": "read",
                "resource": f"custom:file_{worker_id}",
                "agent_id": claimed_agent,
            },
            headers={"Authorization": f"Bearer tok-{worker_id}"},
            token_principals=token_principals,
        )
        return code, body, expected_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(_worker, i) for i in range(10)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    assert len(results) == 10
    for code, body, expected in results:
        assert code == expected, f"Expected {expected} but got {code}: {body}"


# ==============================================================================
# Adversarial Regression Suite for Finding 01 (Second Remediation)
# ==============================================================================


def test_adversarial_structured_agent_token_without_configured_secret(tmp_path: Path) -> None:
    """Requirement 1: Structured agent token without the configured secret is rejected (401)."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    # Server requires secret token "configured-server-secret"
    code, res = _dispatch(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "fs.read",
            "verb": "read",
            "resource": "res:test",
            "agent_id": "malicious-agent",
        },
        headers={"Authorization": "Bearer agent:malicious-agent"},
        auth_token="configured-server-secret",
    )
    assert code == 401
    assert "missing or invalid Bearer token" in res.get("error", "")

    # Direct resolver check fails closed
    with pytest.raises(
        IdentitySecurityError, match="does not match configured authentication secret"
    ):
        resolve_http_caller_context(
            headers={"authorization": "Bearer agent:malicious-agent"},
            expected_token="configured-server-secret",
        )


def test_adversarial_structured_operator_token_without_configured_secret(tmp_path: Path) -> None:
    """Requirement 2: Structured operator token without configured secret is rejected."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    # 1. Attacker attempts to call admin freeze with operator:attacker when server token is set
    code, res = _dispatch(
        services,
        "/v1/freeze",
        method="POST",
        headers={"Authorization": "Bearer operator:attacker"},
        auth_token="configured-server-secret",
    )
    assert code == 401
    assert "missing or invalid Bearer token" in res.get("error", "")

    # Direct resolver check with configured token fails closed
    with pytest.raises(
        IdentitySecurityError, match="does not match configured authentication secret"
    ):
        resolve_http_caller_context(
            headers={"authorization": "Bearer operator:attacker"},
            expected_token="configured-server-secret",
        )

    # 2. When server token is NOT configured, operator token cannot grant operator privileges
    with pytest.raises(
        IdentitySecurityError, match="cannot grant operator privileges without server configuration"
    ):
        resolve_http_caller_context(
            headers={"authorization": "Bearer operator:attacker"},
            remote_addr="127.0.0.1",
        )


def test_adversarial_structured_approver_token_without_configured_secret(tmp_path: Path) -> None:
    """Requirement 3: Structured approver token without configured secret is rejected."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    # 1. Create a crossing requiring approval
    crossing = services.submit_crossing(
        {"tool": "deploy", "verb": "write", "resource": "prod", "agent_id": "test-agent"},
        execute=False,
    )
    cid = crossing["crossing_id"]

    # 2. Attacker attempts to approve with approver:fake when server token is configured
    code, res = _dispatch(
        services,
        f"/v1/crossings/{cid}/approve",
        method="POST",
        data={"approved": True},
        headers={"Authorization": "Bearer approver:fake-approver"},
        auth_token="configured-server-secret",
    )
    assert code == 401

    # Direct resolver check with configured token fails closed
    with pytest.raises(
        IdentitySecurityError, match="does not match configured authentication secret"
    ):
        resolve_http_caller_context(
            headers={"authorization": "Bearer approver:fake-approver"},
            expected_token="configured-server-secret",
        )

    # When server token is NOT configured, approver:fake still CANNOT grant approver privileges
    with pytest.raises(
        IdentitySecurityError, match="cannot grant approver privileges without server configuration"
    ):
        resolve_http_caller_context(
            headers={"authorization": "Bearer approver:fake-approver"},
            remote_addr="127.0.0.1",
        )


def test_adversarial_valid_configured_secret_with_bound_principal(tmp_path: Path) -> None:
    """Requirement 4: Valid configured secret correctly binds and authenticates caller."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    # 1. Shared operator secret authenticates as operator
    code, res = _dispatch(
        services,
        "/v1/freeze",
        method="POST",
        headers={"Authorization": "Bearer valid-operator-secret"},
        auth_token="valid-operator-secret",
    )
    assert code == 200
    assert res.get("frozen") is True

    # 2. Principal mapping in token_principals binds strictly
    token_principals = {
        "agent-token-123": {
            "principal_id": "agent-legit-01",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["agent-legit-01"],
            "scopes": ["crossings:propose", "crossings:read"],
        }
    }
    code, res = _dispatch(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "fs.read",
            "verb": "read",
            "resource": "res:data",
            "agent_id": "agent-legit-01",
        },
        headers={"Authorization": "Bearer agent-token-123"},
        token_principals=token_principals,
    )
    assert code == 200
    assert res.get("verdict") == "allow"


def test_adversarial_invalid_configured_secret(tmp_path: Path) -> None:
    """Requirement 5: Invalid configured secret fails closed (401)."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    code, res = _dispatch(
        services,
        "/v1/crossings",
        method="POST",
        data={"tool": "fs.read", "verb": "read", "resource": "res:test"},
        headers={"Authorization": "Bearer incorrect-secret-token"},
        auth_token="production-secret-token",
    )
    assert code == 401
    assert "missing or invalid Bearer token" in res.get("error", "")

    with pytest.raises(
        IdentitySecurityError, match="does not match configured authentication secret"
    ):
        resolve_http_caller_context(
            headers={"authorization": "Bearer incorrect-secret-token"},
            expected_token="production-secret-token",
        )


def test_adversarial_missing_authentication(tmp_path: Path) -> None:
    """Requirement 6: Missing or malformed authentication credentials fail closed (401)."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    # No Authorization header
    code, res = _dispatch(
        services,
        "/v1/crossings",
        method="POST",
        data={"tool": "fs.read", "verb": "read", "resource": "res:test"},
        auth_token="production-secret-token",
    )
    assert code == 401

    # Malformed non-Bearer authorization header
    code, res = _dispatch(
        services,
        "/v1/crossings",
        method="POST",
        data={"tool": "fs.read", "verb": "read", "resource": "res:test"},
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
        auth_token="production-secret-token",
    )
    assert code == 401

    # Empty bearer token
    code, res = _dispatch(
        services,
        "/v1/crossings",
        method="POST",
        data={"tool": "fs.read", "verb": "read", "resource": "res:test"},
        headers={"Authorization": "Bearer "},
        auth_token="production-secret-token",
    )
    assert code == 401


def test_adversarial_caller_supplied_parent_identity(tmp_path: Path) -> None:
    """Requirement 7: Caller asserting parent identity without authorized delegation is rejected."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    token_principals = {
        "tok-child": {
            "principal_id": "unauthorized-child",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["unauthorized-child"],
            "scopes": ["crossings:propose", "crossings:read"],
        }
    }

    # 1. Attacker attempts to supply parent via X-Actentra-Parent header
    code, res = _dispatch(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "fs.read",
            "verb": "read",
            "resource": "res:test",
            "agent_id": "parent-agent",
        },
        headers={
            "Authorization": "Bearer tok-child",
            "X-Actentra-Parent": "parent-agent",
        },
        token_principals=token_principals,
    )
    assert code == 403
    assert res.get("code") == "unauthorized_principal"

    # 2. Attacker attempts to supply parent via JSON payload
    code, res = _dispatch(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "fs.read",
            "verb": "read",
            "resource": "res:test",
            "agent_id": "parent-agent",
            "parent_agent_id": "parent-agent",
        },
        headers={"Authorization": "Bearer tok-child"},
        token_principals=token_principals,
    )
    assert code == 403
    assert res.get("code") == "unauthorized_principal"


def test_adversarial_caller_supplied_delegated_by_identity(tmp_path: Path) -> None:
    """Requirement 8: Caller-supplied X-Actentra-Delegated-By cannot grant authority over victim."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    token_principals = {
        "tok-attacker": {
            "principal_id": "attacker-agent",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["attacker-agent"],
            "scopes": ["crossings:propose", "crossings:read", "handoffs:advance"],
        }
    }

    # Attacker passes valid token for attacker, but asserts X-Actentra-Delegated-By: victim-agent
    code, res = _dispatch(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "fs.read",
            "verb": "read",
            "resource": "res:test",
            "agent_id": "victim-agent",
        },
        headers={
            "Authorization": "Bearer tok-attacker",
            "X-Actentra-Delegated-By": "victim-agent",
        },
        token_principals=token_principals,
    )
    assert code == 403
    assert res.get("code") == "unauthorized_principal"
    assert "not an authorized delegate of 'victim-agent'" in res.get("error", "")


def test_adversarial_child_attempting_to_exceed_parent_scopes(tmp_path: Path) -> None:
    """Requirement 9: Child cannot receive scopes that the parent delegator does not possess."""
    token_principals = {
        "tok-parent": {
            "principal_id": "parent-agent",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["parent-agent"],
            "scopes": ["handoffs:advance", "crossings:read"],
        },
        "tok-child-escalating": {
            "principal_id": "child-agent",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["child-agent", "parent-agent"],
            "delegated_by": "parent-agent",
            # Child attempts to claim crossings:execute and system:admin, which parent lacks!
            "scopes": ["handoffs:advance", "crossings:execute", "system:admin"],
        },
    }

    with pytest.raises(
        IdentitySecurityError,
        match="Delegation scope violation: child 'child-agent' has scope 'crossings:execute'",
    ):
        resolve_http_caller_context(
            headers={"authorization": "Bearer tok-child-escalating"},
            token_principals=token_principals,
        )


def test_adversarial_child_attempting_to_represent_unauthorized_agent(tmp_path: Path) -> None:
    """Requirement 10: Child cannot represent an agent that parent lacks authority to represent."""
    token_principals = {
        "tok-parent": {
            "principal_id": "parent-agent",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["parent-agent"],
            "scopes": ["handoffs:advance"],
        },
        "tok-child-broad": {
            "principal_id": "child-agent",
            "principal_type": "authenticated_agent",
            # Child attempts to represent unauthorized-victim, which parent cannot represent!
            "allowed_agents": ["child-agent", "parent-agent", "unauthorized-victim"],
            "delegated_by": "parent-agent",
            "scopes": ["handoffs:advance"],
        },
    }

    with pytest.raises(
        IdentitySecurityError,
        match="Delegation agent violation: child 'child-agent'",
    ):
        resolve_http_caller_context(
            headers={"authorization": "Bearer tok-child-broad"},
            token_principals=token_principals,
        )


def test_adversarial_revoked_or_invalid_delegation(tmp_path: Path) -> None:
    """Requirement 11: Revoked, expired, or invalid delegation fails closed."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    # 1. Register legitimate dynamic delegation
    parent_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="parent-agent",
        authenticated=True,
        trust_domain="gateway_agent",
        scopes=("handoffs:advance", "handoffs:create"),
        allowed_agents=("parent-agent",),
    )
    grant_info = services.register_delegation(
        delegator_id="parent-agent",
        delegatee_id="child-agent",
        allowed_agents=["parent-agent"],
        scopes=["handoffs:advance"],
        grant_id="grant-test-revocation-01",
        caller_context=parent_ctx,
    )
    gid = grant_info["grant_id"]

    token_principals = {
        "tok-child": {
            "principal_id": "child-agent",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["child-agent"],
            "scopes": ["handoffs:advance"],
        }
    }

    # Create task handoff assigned to parent-agent
    handoff = services.create_task_handoff(
        task_id="task-revocation-01",
        initiator_agent_id="parent-agent",
        assigned_agent_id="parent-agent",
        verifier_agent_id="agent-auditor",
        allowed_verbs=["read", "write"],
    )
    hid = handoff["handoff_id"]

    # 2. Before revocation, child can advance handoff with valid grant
    code, res = _dispatch(
        services,
        f"/v1/handoffs/{hid}/advance",
        method="POST",
        data={"caller_agent_id": "parent-agent", "next_agent_id": "agent-auditor"},
        headers={
            "Authorization": "Bearer tok-child",
            "X-Actentra-Delegated-By": "parent-agent",
            "X-Actentra-Delegation-Grant": gid,
        },
        token_principals=token_principals,
    )
    assert code == 200

    # 3. Parent revokes the delegation grant
    revoked = services.revoke_delegation(gid, caller_context=parent_ctx)
    assert revoked is True

    # 4. Create another handoff
    handoff2 = services.create_task_handoff(
        task_id="task-revocation-02",
        initiator_agent_id="parent-agent",
        assigned_agent_id="parent-agent",
        verifier_agent_id="agent-auditor",
        allowed_verbs=["read", "write"],
    )
    hid2 = handoff2["handoff_id"]

    # 5. Child attempts to advance after revocation -> FAILS CLOSED (403)
    code, res = _dispatch(
        services,
        f"/v1/handoffs/{hid2}/advance",
        method="POST",
        data={"caller_agent_id": "parent-agent", "next_agent_id": "agent-auditor"},
        headers={
            "Authorization": "Bearer tok-child",
            "X-Actentra-Delegated-By": "parent-agent",
            "X-Actentra-Delegation-Grant": gid,
        },
        token_principals=token_principals,
    )
    assert code == 403
    assert "invalid or revoked" in res.get("error", "").lower()


def test_adversarial_legitimate_authorized_delegation(tmp_path: Path) -> None:
    """Requirement 12: Legitimate authorized delegation succeeds within assigned scopes."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    token_principals = {
        "tok-parent": {
            "principal_id": "agent-builder",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["agent-builder"],
            "scopes": ["handoffs:advance", "handoffs:create"],
        },
        "tok-subagent": {
            "principal_id": "subagent-worker-1",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["subagent-worker-1", "agent-builder"],
            "delegated_by": "agent-builder",
            "scopes": ["handoffs:advance"],
        },
    }

    handoff = services.create_task_handoff(
        task_id="task-legit-delegation",
        initiator_agent_id="agent-builder",
        assigned_agent_id="agent-builder",
        verifier_agent_id="agent-auditor",
        allowed_verbs=["read", "write"],
    )
    hid = handoff["handoff_id"]

    code, res = _dispatch(
        services,
        f"/v1/handoffs/{hid}/advance",
        method="POST",
        data={
            "caller_agent_id": "agent-builder",
            "next_agent_id": "agent-auditor",
            "output_artifacts": ["delegated-work.txt"],
        },
        headers={"Authorization": "Bearer tok-subagent"},
        token_principals=token_principals,
    )
    assert code == 200
    assert res["status"] == "active"
    assert res["assigned_agent_id"] == "agent-auditor"


def test_adversarial_direct_services_layer_delegation_forgery(tmp_path: Path) -> None:
    """Requirement 13: Direct services-layer invocation with forged CallerContext fails closed."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    # Forged CallerContext in Python without any registered grant in services.delegation_registry
    forged_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="attacker-agent",
        authenticated=True,
        trust_domain="fake_domain",
        scopes=("handoffs:advance", "crossings:propose"),
        allowed_agents=("attacker-agent", "victim-agent"),
        delegated_by="victim-agent",
    )

    # 1. Direct submit_crossing call with forged context
    res = services.submit_crossing(
        {"tool": "fs.read", "verb": "read", "resource": "res:secret", "agent_id": "victim-agent"},
        caller_context=forged_ctx,
    )
    assert res.get("verdict") == "deny"
    assert res.get("code") == "unauthorized_principal"
    assert "Forged delegation context" in res.get("error", "")

    # 2. Direct advance_task_handoff call with forged context
    handoff = services.create_task_handoff(
        task_id="task-direct-forgery",
        initiator_agent_id="victim-agent",
        assigned_agent_id="victim-agent",
        verifier_agent_id="agent-auditor",
        allowed_verbs=["read"],
    )
    with pytest.raises(IdentitySecurityError, match="Forged delegation context"):
        services.advance_task_handoff(
            handoff["handoff_id"],
            caller_agent_id="victim-agent",
            next_agent_id="agent-auditor",
            caller_context=forged_ctx,
        )


def test_adversarial_concurrent_identity_and_delegation_isolation(tmp_path: Path) -> None:
    """Requirement 14: Concurrent requests preserve identity and delegation isolation."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_SECURITY_TEST_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    token_principals = {
        "tok-legit-alpha": {
            "principal_id": "agent-alpha",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["agent-alpha"],
            "scopes": ["crossings:propose", "crossings:read"],
        },
        "tok-legit-beta": {
            "principal_id": "agent-beta",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["agent-beta", "agent-alpha"],
            "delegated_by": "agent-alpha",
            "scopes": ["crossings:propose", "crossings:read"],
        },
        "tok-attacker-gamma": {
            "principal_id": "agent-gamma",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["agent-gamma"],
            "scopes": ["crossings:propose", "crossings:read"],
        },
    }

    results: list[tuple[int, int, str]] = []

    def _worker(thread_idx: int) -> tuple[int, int, str]:
        mode = thread_idx % 4
        if mode == 0:
            # Legit Alpha proposing as Alpha -> 200
            code, body = _dispatch(
                services,
                "/v1/crossings",
                method="POST",
                data={
                    "tool": "fs.read",
                    "verb": "read",
                    "resource": f"res:{thread_idx}",
                    "agent_id": "agent-alpha",
                },
                headers={"Authorization": "Bearer tok-legit-alpha"},
                token_principals=token_principals,
            )
            return code, 200, "legit-alpha"
        elif mode == 1:
            # Legit Beta delegated by Alpha proposing as Alpha -> 200
            code, body = _dispatch(
                services,
                "/v1/crossings",
                method="POST",
                data={
                    "tool": "fs.read",
                    "verb": "read",
                    "resource": f"res:{thread_idx}",
                    "agent_id": "agent-alpha",
                },
                headers={"Authorization": "Bearer tok-legit-beta"},
                token_principals=token_principals,
            )
            return code, 200, "legit-beta"
        elif mode == 2:
            # Attacker Gamma asserting forged delegation to Alpha -> 403
            code, body = _dispatch(
                services,
                "/v1/crossings",
                method="POST",
                data={
                    "tool": "fs.read",
                    "verb": "read",
                    "resource": f"res:{thread_idx}",
                    "agent_id": "agent-alpha",
                },
                headers={
                    "Authorization": "Bearer tok-attacker-gamma",
                    "X-Actentra-Delegated-By": "agent-alpha",
                },
                token_principals=token_principals,
            )
            return code, 403, "attacker-gamma"
        else:
            # Attacker Gamma trying structured operator token -> 401 (fails auth check)
            code, body = _dispatch(
                services,
                "/v1/crossings",
                method="POST",
                data={
                    "tool": "fs.read",
                    "verb": "read",
                    "resource": f"res:{thread_idx}",
                    "agent_id": "agent-alpha",
                },
                headers={"Authorization": "Bearer operator:gamma-attacker"},
                token_principals=token_principals,
            )
            return code, 401, "operator-attacker"

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(_worker, i) for i in range(24)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    assert len(results) == 24
    for actual_code, expected_code, role in results:
        assert actual_code == expected_code, (
            f"Role {role} got status {actual_code}, expected {expected_code}"
        )
