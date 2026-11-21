"""Comprehensive Phase 2 tests for session isolation, durable budgets, taint integrity,
and HTTP route authorization.

Tests:
1. Server-controlled session creation, validation, and cross-principal access rejection.
2. Session ID substitution rejection (preventing session hijacking).
3. Dual-tier durable budget enforcement (session and principal limits) and durability.
4. Concurrent budget consumption safety.
5. Durable taint integrity: taint inheritance across sessions and unauthorized reset rejection.
6. HTTP route-to-scope authorization matrix for all endpoints.
7. Object-level authorization and sensitive parameter redaction for pending approvals.
8. Cross-session and cross-principal receipt isolation.
9. Direct AppServices API authorization enforcement (no internal bypass).
10. Session revocation and expiration enforcement.
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
)
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_core.verdict import Verdict
from actentra_gateway.http_service import ActentraHTTPHandler
from actentra_gateway.services import AppServices, ExecutorRegistry

_POLICY_YAML = """
version: 1
policy_id: test-phase2-policy
mode: enforce
defaults:
  verdict: deny
  reason: "Default fail-closed"
limits:
  - id: principal-rate-limit
    scope: principal
    max_actions_per_minute: 10
budgets:
  max_actions: 2
  principal_max_actions: 3
  on_exceeded: deny
rules:
  - id: allow-calc
    match: { tool: calc, verb: read }
    verdict: allow
  - id: ask-transfer
    match: { tool: transfer, verb: write }
    verdict: ask
    reason: "Transfer requires human approval"
  - id: block-untrusted-egress
    match: { tool: egress, taint: untrusted }
    verdict: deny
    reason: "Untrusted taint blocks external egress"
  - id: allow-egress
    match: { tool: egress, verb: write }
    verdict: allow
"""


def _make_services(
    db_path: Path,
    session_id: str = "default-sess",
    policy_yaml: str = _POLICY_YAML,
) -> AppServices:
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(policy_yaml)
    boundary = Boundary(policy=policy, receipt_store=store, session_id=session_id)
    registry = ExecutorRegistry()
    registry.register("calc", lambda env, dec: {"calc": True})
    registry.register("egress", lambda env, dec: {"egress": True})
    registry.register("transfer", lambda env, dec: {"transfer": True})
    return AppServices(boundary, executor_registry=registry)


def _dispatch_http(
    services: AppServices,
    path: str,
    method: str = "GET",
    data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    token_principals: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    handler = ActentraHTTPHandler.__new__(ActentraHTTPHandler)
    server_mock = MagicMock()
    server_mock.services = services
    server_mock.boundary = services.boundary
    server_mock.auth_token = "secret-operator-token"
    server_mock.token_principals = token_principals or {}
    server_mock.delegation_registry = services.delegation_registry
    handler.server = server_mock
    handler.request_version = "HTTP/1.1"
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.close_connection = True
    handler.path = path
    handler.wfile = io.BytesIO()

    body_bytes = json.dumps(data).encode("utf-8") if data is not None else b""
    hdrs = {
        "Content-Length": str(len(body_bytes)),
        "Content-Type": "application/json",
    }
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
    elif method == "OPTIONS":
        handler.do_OPTIONS()

    raw_output = handler.wfile.getvalue().decode("utf-8")
    status_line = raw_output.splitlines()[0]
    status_code = int(status_line.split()[1])

    parts = raw_output.split("\r\n\r\n", 1)
    body_str = parts[1] if len(parts) > 1 else ""
    try:
        parsed_body = json.loads(body_str) if body_str else None
    except json.JSONDecodeError:
        parsed_body = body_str

    return status_code, parsed_body


# --- 1. Server-Controlled Session Identity & Hijacking Rejection ---


def test_server_controlled_session_creation_and_ownership(tmp_path: Path) -> None:
    """Server issues cryptographically sound session bound to principal; rejects cross access."""
    services = _make_services(tmp_path / "sess_ident.db")

    agent_scopes = (
        "sessions:create",
        "sessions:read",
        "crossings:submit",
        "crossings:propose",
        "crossings:execute",
    )
    ctx_alice = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="alice",
        authenticated=True,
        trust_domain="tenant-corp",
        scopes=agent_scopes,
        allowed_agents=("alice",),
    )
    ctx_bob = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="bob",
        authenticated=True,
        trust_domain="tenant-corp",
        scopes=agent_scopes,
        allowed_agents=("bob",),
    )

    # 1. Alice creates a server session
    sess = services.create_session(caller_context=ctx_alice)
    sid = sess["session_id"]
    assert sid.startswith("sess-")
    assert sess["principal_id"] == "alice"
    assert sess["status"] == "active"

    # 2. Alice reads her own session
    alice_read = services.get_session(sid, caller_context=ctx_alice)
    assert alice_read is not None
    assert alice_read["session_id"] == sid

    # 3. Bob attempts to read Alice's session -> Rejected
    with pytest.raises(IdentitySecurityError, match="cannot read session"):
        services.get_session(sid, caller_context=ctx_bob)

    # 4. Bob attempts to submit a crossing using Alice's session ID -> Denied / Hijack attempt
    crossing_res = services.submit_crossing(
        {
            "tool": "calc",
            "verb": "read",
            "resource": "tool:calc",
            "session_id": sid,
            "agent_id": "bob",
        },
        caller_context=ctx_bob,
    )
    assert crossing_res["verdict"] == Verdict.DENY.value
    assert crossing_res["rule_id"] == "identity:cross-principal-session-access"
    assert "session-hijack" in crossing_res["risk_tags"]


def test_session_id_substitution_via_http_gateway(tmp_path: Path) -> None:
    """Attacker attempting session ID substitution over HTTP is rejected with 403."""
    services = _make_services(tmp_path / "http_hijack.db")

    token_principals = {
        "tok-alice": {
            "principal_id": "alice",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["alice"],
            "scopes": [
                "sessions:create",
                "sessions:read",
                "crossings:submit",
                "crossings:propose",
                "crossings:execute",
            ],
        },
        "tok-attacker": {
            "principal_id": "attacker",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["attacker"],
            "scopes": [
                "sessions:create",
                "sessions:read",
                "crossings:submit",
                "crossings:propose",
                "crossings:execute",
            ],
        },
    }

    # 1. Alice creates session via HTTP
    code, alice_sess = _dispatch_http(
        services,
        "/v1/sessions",
        method="POST",
        headers={"Authorization": "Bearer tok-alice"},
        token_principals=token_principals,
    )
    assert code == 201
    alice_sid = alice_sess["session_id"]

    # 2. Attacker attempts to read Alice's session -> 403
    code, err_resp = _dispatch_http(
        services,
        f"/v1/sessions/{alice_sid}",
        method="GET",
        headers={"Authorization": "Bearer tok-attacker"},
        token_principals=token_principals,
    )
    assert code == 403

    # 3. Attacker attempts crossing using Alice's session -> Denied (verdict deny)
    code, crossing_resp = _dispatch_http(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "calc",
            "verb": "read",
            "resource": "tool:calc",
            "session_id": alice_sid,
            "agent_id": "attacker",
        },
        headers={"Authorization": "Bearer tok-attacker"},
        token_principals=token_principals,
    )
    assert code == 403
    assert crossing_resp["verdict"] == "deny"


# --- 2. Durable Budget Enforcement (Session vs Principal Cumulative) ---


def test_durable_dual_tier_budget_enforcement(tmp_path: Path) -> None:
    """Action budget enforces session limit (2) and principal limit (3) across sessions."""
    db_file = tmp_path / "dual_budget.db"
    services = _make_services(db_file)

    ctx_agent = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="budgeted-agent",
        authenticated=True,
        trust_domain="tenant-test",
        scopes=("crossings:submit", "crossings:propose", "crossings:execute", "sessions:create"),
        allowed_agents=("budgeted-agent",),
    )

    # Session 1: create session record
    sess1 = services.create_session(caller_context=ctx_agent)
    sid1 = sess1["session_id"]

    # Action 1 in sess1 -> OK (session 1/2, principal 1/3)
    r1 = services.submit_crossing(
        {"tool": "calc", "verb": "read", "resource": "res1", "session_id": sid1},
        execute=True,
        caller_context=ctx_agent,
    )
    assert r1["verdict"] == "allow"
    assert r1["outcome"]["status"] == "success"

    # Action 2 in sess1 -> OK (session 2/2, principal 2/3)
    r2 = services.submit_crossing(
        {"tool": "calc", "verb": "read", "resource": "res2", "session_id": sid1},
        execute=True,
        caller_context=ctx_agent,
    )
    assert r2["verdict"] == "allow"
    assert r2["outcome"]["status"] == "success"

    # Action 3 in sess1 -> Session budget exceeded (max_actions: 2) -> DENY
    r3 = services.submit_crossing(
        {"tool": "calc", "verb": "read", "resource": "res3", "session_id": sid1},
        execute=True,
        caller_context=ctx_agent,
    )
    assert r3["verdict"] == "deny"
    assert r3["rule_id"] == "budget:max-actions-exceeded"

    # Attacker attempts bypass by opening Session 2
    sess2 = services.create_session(caller_context=ctx_agent)
    sid2 = sess2["session_id"]

    # Action 4 in sess2 (Session 1/2, but Principal 3/3) -> OK
    r4 = services.submit_crossing(
        {"tool": "calc", "verb": "read", "resource": "res4", "session_id": sid2},
        execute=True,
        caller_context=ctx_agent,
    )
    assert r4["verdict"] == "allow"
    assert r4["outcome"]["status"] == "success"

    # Action 5 in sess2 (Session 2/2, but Principal 4/3) -> PRINCIPAL BUDGET EXCEEDED -> DENY
    r5 = services.submit_crossing(
        {"tool": "calc", "verb": "read", "resource": "res5", "session_id": sid2},
        execute=True,
        caller_context=ctx_agent,
    )
    assert r5["verdict"] == "deny"
    assert r5["rule_id"] == "budget:principal-max-actions-exceeded"
    assert "Principal cumulative actions limit" in r5["reason"]


def test_budget_durability_across_process_restart(tmp_path: Path) -> None:
    """Cumulative budgets survive process restarts by reading durable SQLite counters."""
    db_file = tmp_path / "restart_budget.db"

    ctx_agent = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="persistent-agent",
        authenticated=True,
        trust_domain="tenant-test",
        scopes=("crossings:submit", "crossings:propose", "crossings:execute", "sessions:create"),
        allowed_agents=("persistent-agent",),
    )

    # Process 1: Consume 2 actions
    services1 = _make_services(db_file)
    sess1 = services1.create_session(caller_context=ctx_agent)
    sid = sess1["session_id"]

    r1 = services1.submit_crossing(
        {"tool": "calc", "verb": "read", "resource": "r1", "session_id": sid},
        execute=True,
        caller_context=ctx_agent,
    )
    assert r1["verdict"] == "allow"

    r2 = services1.submit_crossing(
        {"tool": "calc", "verb": "read", "resource": "r2", "session_id": sid},
        execute=True,
        caller_context=ctx_agent,
    )
    assert r2["verdict"] == "allow"

    # Process 1 crashes / terminates
    del services1

    # Process 2 starts up pointing to the same SQLite database
    services2 = _make_services(db_file)

    # Action 3 in sess1 should immediately be blocked by session budget (2/2 already consumed in DB)
    r3 = services2.submit_crossing(
        {"tool": "calc", "verb": "read", "resource": "r3", "session_id": sid},
        execute=True,
        caller_context=ctx_agent,
    )
    assert r3["verdict"] == "deny"
    assert r3["rule_id"] == "budget:max-actions-exceeded"

    # Action in a new session: allows only 1 more action before hitting principal limit of 3
    sess2 = services2.create_session(caller_context=ctx_agent)
    r4 = services2.submit_crossing(
        {"tool": "calc", "verb": "read", "resource": "r4", "session_id": sess2["session_id"]},
        execute=True,
        caller_context=ctx_agent,
    )
    assert r4["verdict"] == "allow"

    # 4th total action across sessions is blocked by principal cumulative limit
    r5 = services2.submit_crossing(
        {"tool": "calc", "verb": "read", "resource": "r5", "session_id": sess2["session_id"]},
        execute=True,
        caller_context=ctx_agent,
    )
    assert r5["verdict"] == "deny"
    assert r5["rule_id"] == "budget:principal-max-actions-exceeded"


def test_concurrent_budget_consumption_transactional_safety(tmp_path: Path) -> None:
    """Concurrent requests update budget counters transactionally without race condition bypass."""
    db_file = tmp_path / "concurrent_budget.db"
    services = _make_services(db_file)

    ctx_agent = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="concurrent-agent",
        authenticated=True,
        trust_domain="tenant-test",
        scopes=("crossings:submit", "crossings:propose", "crossings:execute", "sessions:create"),
        allowed_agents=("concurrent-agent",),
    )

    sess = services.create_session(caller_context=ctx_agent)
    sid = sess["session_id"]

    # Concurrently issue 10 crossing executions
    def _execute_action(i: int) -> str:
        res = services.submit_crossing(
            {"tool": "calc", "verb": "read", "resource": f"res-{i}", "session_id": sid},
            execute=True,
            caller_context=ctx_agent,
        )
        return str(res["verdict"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        verdicts = list(executor.map(_execute_action, range(10)))

    # Only 2 executions must succeed for this session (max_actions: 2)
    allowed_count = verdicts.count("allow")
    denied_count = verdicts.count("deny")

    assert allowed_count == 2
    assert denied_count == 8


# --- 3. Taint Integrity Across Sessions & Unauthorized Reset Prevention ---


def test_durable_taint_integrity_across_sessions_and_resets(tmp_path: Path) -> None:
    """Taint is persisted durably and bound to principal; new session inherits taint."""
    db_file = tmp_path / "taint_integrity.db"
    services = _make_services(db_file)

    ctx_agent = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="tainted-agent",
        authenticated=True,
        trust_domain="tenant-test",
        scopes=("crossings:submit", "crossings:propose", "crossings:execute", "sessions:create"),
        allowed_agents=("tainted-agent",),
    )
    ctx_operator = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_OPERATOR,
        principal_id="sec-operator",
        authenticated=True,
        trust_domain="security-domain",
        scopes=("*",),
        allowed_agents=("*",),
    )

    # 1. Agent starts in Session 1 and ingests untrusted data
    sess1 = services.create_session(caller_context=ctx_agent)
    sid1 = sess1["session_id"]

    sub1 = services.submit_crossing(
        {
            "tool": "calc",
            "verb": "read",
            "resource": "doc1",
            "session_id": sid1,
            "provenance": [{"source": "web", "trust": "untrusted"}],
        },
        execute=True,
        caller_context=ctx_agent,
    )
    assert sub1["verdict"] == "allow"

    # Egress in Session 1 is blocked because session is untrusted
    egress1 = services.submit_crossing(
        {
            "tool": "egress",
            "verb": "write",
            "resource": "https://attacker.com",
            "session_id": sid1,
        },
        execute=True,
        caller_context=ctx_agent,
    )
    assert egress1["verdict"] == "deny"
    assert egress1["rule_id"] == "block-untrusted-egress"

    # 2. Attacker creates Session 2 to bypass taint
    sess2 = services.create_session(caller_context=ctx_agent)
    sid2 = sess2["session_id"]

    # Egress in Session 2 MUST STILL BE BLOCKED because principal taint is durable
    egress2 = services.submit_crossing(
        {
            "tool": "egress",
            "verb": "write",
            "resource": "https://attacker.com",
            "session_id": sid2,
        },
        execute=True,
        caller_context=ctx_agent,
    )
    assert egress2["verdict"] == "deny"
    assert egress2["rule_id"] == "block-untrusted-egress"

    # 3. Attacker attempts to clear taint directly without operator privilege -> REJECTED
    with pytest.raises(IdentitySecurityError, match="authorized operators"):
        services.boundary.set_session_taint("clean", session_id=sid2, caller_context=ctx_agent)

    # 4. Authorized operator clears taint
    services.boundary.set_session_taint(
        "clean",
        session_id=sid2,
        principal_id="tainted-agent",
        caller_context=ctx_operator,
    )

    # Now clean egress is allowed
    egress3 = services.submit_crossing(
        {
            "tool": "egress",
            "verb": "write",
            "resource": "https://clean-site.com",
            "session_id": sid2,
        },
        execute=True,
        caller_context=ctx_agent,
    )
    assert egress3["verdict"] == "allow"


# --- 4. HTTP Route Authorization & Scopes Matrix ---


def test_http_route_scope_matrix_enforcement(tmp_path: Path) -> None:
    """Every GET and read endpoint enforces explicit route-to-scope authorization matrix."""
    services = _make_services(tmp_path / "route_auth.db")

    token_principals = {
        "tok-unprivileged": {
            "principal_id": "agent-no-scopes",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["agent-no-scopes"],
            "scopes": ["crossings:submit", "crossings:propose"],
        },
        "tok-auditor": {
            "principal_id": "auditor-dave",
            "principal_type": "authenticated_operator",
            "scopes": [
                "receipts:read",
                "audit:verify",
                "audit:export",
                "policies:read",
                "observations:read",
                "evidence:read",
                "leases:read",
                "handoffs:read",
                "sessions:read",
                "approvals:read",
            ],
        },
    }

    protected_endpoints = [
        ("/v1/receipts", "GET"),
        ("/v1/verify", "GET"),
        ("/v1/policy", "GET"),
        ("/v1/policy/lint", "GET"),
        ("/v1/bundle/export", "GET"),
        ("/v1/observations", "GET"),
        ("/v1/evidence", "GET"),
        ("/v1/leases", "GET"),
        ("/v1/handoffs", "GET"),
        ("/v1/sessions", "GET"),
        ("/ui", "GET"),
    ]

    for endpoint, method in protected_endpoints:
        # Unprivileged agent is rejected with 403 Forbidden
        code, resp = _dispatch_http(
            services,
            endpoint,
            method=method,
            headers={"Authorization": "Bearer tok-unprivileged"},
            token_principals=token_principals,
        )
        assert code == 403, f"Endpoint {endpoint} should require scope authorization"
        assert resp["code"] == "insufficient_scope"

        # Authorized auditor succeeds with 200 OK
        code_ok, _ = _dispatch_http(
            services,
            endpoint,
            method=method,
            headers={"Authorization": "Bearer tok-auditor"},
            token_principals=token_principals,
        )
        assert code_ok == 200, f"Endpoint {endpoint} failed for auditor: {code_ok}"


# --- 5. Object-Level Authorization & Sensitive Parameter Redaction ---


def test_object_level_authorization_and_parameter_redaction(tmp_path: Path) -> None:
    """Non-operators with approvals:read cannot see sensitive params of other principals."""
    services = _make_services(tmp_path / "redaction.db")

    token_principals = {
        "tok-alice": {
            "principal_id": "alice",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["alice"],
            "scopes": ["crossings:submit", "crossings:propose", "sessions:create"],
        },
        "tok-viewer": {
            "principal_id": "viewer-bob",
            "principal_type": "authenticated_agent",
            "allowed_agents": ["viewer-bob"],
            "scopes": ["approvals:read", "crossings:read", "approvals:read_all"],
        },
        "tok-operator": {
            "principal_id": "root-operator",
            "principal_type": "authenticated_operator",
            "scopes": ["*"],
        },
    }

    # 1. Alice creates session and submits crossing requiring approval (holding sensitive secret)
    code, s_res = _dispatch_http(
        services,
        "/v1/sessions",
        method="POST",
        headers={"Authorization": "Bearer tok-alice"},
        token_principals=token_principals,
    )
    alice_sid = s_res["session_id"]

    code, cross_res = _dispatch_http(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "transfer",
            "verb": "write",
            "resource": "account:target",
            "params": {"api_key": "SUPER_SECRET_TOKEN_XYZ", "amount": 10000},
            "session_id": alice_sid,
        },
        headers={"Authorization": "Bearer tok-alice"},
        token_principals=token_principals,
    )
    assert cross_res["verdict"] == "ask"
    cid = cross_res["crossing_id"]

    # 2. Viewer Bob reads pending approvals list
    code, bob_view = _dispatch_http(
        services,
        "/v1/crossings/pending",
        method="GET",
        headers={"Authorization": "Bearer tok-viewer"},
        token_principals=token_principals,
    )
    assert code == 200
    assert len(bob_view) == 1
    # Bob should see the crossing but params MUST be redacted
    assert bob_view[0]["params"] == {"_redacted": "UNAUTHORIZED_RESOURCE_ACCESS"}

    # 3. Viewer Bob reads single pending approval detail
    code, bob_detail = _dispatch_http(
        services,
        f"/v1/crossings/{cid}",
        method="GET",
        headers={"Authorization": "Bearer tok-viewer"},
        token_principals=token_principals,
    )
    assert code == 200
    assert bob_detail["params"] == {"_redacted": "UNAUTHORIZED_RESOURCE_ACCESS"}

    # 4. Operator reads pending approval -> params UNREDACTED
    code, op_view = _dispatch_http(
        services,
        f"/v1/crossings/{cid}",
        method="GET",
        headers={"Authorization": "Bearer tok-operator"},
        token_principals=token_principals,
    )
    assert code == 200
    assert op_view["params"]["api_key"] == "SUPER_SECRET_TOKEN_XYZ"


# --- 6. Cross-Session Receipt Access Partitioning ---


def test_cross_session_receipt_isolation(tmp_path: Path) -> None:
    """Non-operator callers cannot query receipts belonging to other sessions."""
    services = _make_services(tmp_path / "receipt_isolation.db")

    agent_scopes = (
        "crossings:submit",
        "crossings:propose",
        "crossings:execute",
        "receipts:read",
        "sessions:create",
    )
    ctx_alice = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="alice",
        authenticated=True,
        trust_domain="tenant-test",
        scopes=agent_scopes,
        allowed_agents=("alice",),
    )
    ctx_bob = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="bob",
        authenticated=True,
        trust_domain="tenant-test",
        scopes=agent_scopes,
        allowed_agents=("bob",),
    )

    sess_alice = services.create_session(caller_context=ctx_alice)
    sess_bob = services.create_session(caller_context=ctx_bob)

    # Alice and Bob generate receipts in their respective sessions
    services.submit_crossing(
        {
            "tool": "calc",
            "verb": "read",
            "resource": "alice-res",
            "session_id": sess_alice["session_id"],
        },
        execute=True,
        caller_context=ctx_alice,
    )
    services.submit_crossing(
        {
            "tool": "calc",
            "verb": "read",
            "resource": "bob-res",
            "session_id": sess_bob["session_id"],
        },
        execute=True,
        caller_context=ctx_bob,
    )

    # Bob attempts to query Alice's session receipts explicitly -> REJECTED
    with pytest.raises(IdentitySecurityError, match="cannot access receipts"):
        services.query_receipts(session_id=sess_alice["session_id"], caller_context=ctx_bob)

    # Bob queries general receipts -> only his own receipts returned
    bob_receipts = services.query_receipts(caller_context=ctx_bob)
    assert len(bob_receipts["records"]) == 2
    assert all(r["session_id"] == sess_bob["session_id"] for r in bob_receipts["records"])


# --- 7. Direct AppServices API Authorization ---


def test_direct_app_services_api_authorization(tmp_path: Path) -> None:
    """Internal service APIs enforce caller_context and cannot be used to bypass security checks."""
    services = _make_services(tmp_path / "direct_api.db")

    ctx_unprivileged = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="unprivileged-agent",
        authenticated=True,
        trust_domain="tenant-test",
        scopes=(),
        allowed_agents=("unprivileged-agent",),
    )

    with pytest.raises(IdentitySecurityError, match="lacks 'receipts:read' scope"):
        services.query_receipts(caller_context=ctx_unprivileged)

    with pytest.raises(IdentitySecurityError, match="lacks 'policies:read' scope"):
        services.get_policy_yaml(caller_context=ctx_unprivileged)

    with pytest.raises(IdentitySecurityError, match="lacks 'audit:export' scope"):
        services.export_audit_bundle(caller_context=ctx_unprivileged)

    with pytest.raises(IdentitySecurityError, match="lacks 'audit:verify"):
        services.verify_audit_log(caller_context=ctx_unprivileged)

    with pytest.raises(IdentitySecurityError, match="lacks 'observations:read' scope"):
        services.list_observations(caller_context=ctx_unprivileged)

    with pytest.raises(IdentitySecurityError, match="lacks 'leases:read' scope"):
        services.list_resource_leases(caller_context=ctx_unprivileged)

    with pytest.raises(IdentitySecurityError, match="lacks 'handoffs:read' scope"):
        services.list_task_handoffs(caller_context=ctx_unprivileged)

    with pytest.raises(IdentitySecurityError, match="lacks 'sessions:read' scope"):
        services.list_sessions(caller_context=ctx_unprivileged)


# --- 8. Session Revocation & Expiration ---


def test_session_revocation_enforcement(tmp_path: Path) -> None:
    """Revoked sessions cannot be used for subsequent crossings."""
    services = _make_services(tmp_path / "session_revocation.db")

    ctx_agent = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="revocable-agent",
        authenticated=True,
        trust_domain="tenant-test",
        scopes=("crossings:submit", "crossings:propose", "sessions:create", "sessions:revoke"),
        allowed_agents=("revocable-agent",),
    )

    sess = services.create_session(caller_context=ctx_agent)
    sid = sess["session_id"]

    # Action in active session -> OK
    r1 = services.submit_crossing(
        {"tool": "calc", "verb": "read", "resource": "r1", "session_id": sid},
        caller_context=ctx_agent,
    )
    assert r1["verdict"] == "allow"

    # Revoke session
    assert services.revoke_session(sid, caller_context=ctx_agent) is True

    # Action in revoked session -> DENY
    r2 = services.submit_crossing(
        {"tool": "calc", "verb": "read", "resource": "r2", "session_id": sid},
        caller_context=ctx_agent,
    )
    assert r2["verdict"] == "deny"
    assert "has been revoked" in r2["error"]
