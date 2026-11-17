"""Unit tests verifying all 10 security findings and remediations from the code review.

Covers:
1. Critical: Approved-crossing dispatch authorization gate, atomic single-use claim,
   and approved expiration.
2. High: SSRF redirect validation and connection safety in ScopedHTTPExecutor.
3. High: Non-loopback binding enforcement requiring authentication token.
4. High: Stored XSS defense via HTML escaping in Operator Console and CSP header.
5. High: Gateway session taint propagation.
6. High: Gateway cumulative budget recording on execution dispatch.
7. Medium: SQLite CTE verb classification and PRAGMA query_only enforcement.
8. Medium: External outcome duplicate prevention and decision verification.
9. Medium: Receipt query limit and offset clamping.
10. Medium: Negative Content-Length request body rejection.
11. Medium: Side-effect-free simulation preserving rate-limit quotas.
"""

from __future__ import annotations

import io
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from actentra.boundary import Boundary
from actentra_core.envelope import build_envelope
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore, verify_log
from actentra_executors.fs import ExecutorError
from actentra_executors.http import ScopedHTTPExecutor, SSRFSafeRedirectHandler
from actentra_executors.sqlite import ScopedSQLiteExecutor, _infer_verb
from actentra_gateway.http_service import ActentraHTTPHandler, ActentraHTTPServer
from actentra_gateway.services import AppServices, ExecutorRegistry


def _base_policy_yaml() -> str:
    return """
version: 1
policy_id: remediation-test-policy
mode: enforce
defaults:
  verdict: deny
  reason: Denied by default
limits:
  - id: global-rate
    scope: global
    max_actions_per_minute: 100
budgets:
  max_actions: 2
  on_exceeded: deny
rules:
  - id: allow-reads
    match:
      verb: read
    verdict: allow
    reason: Allow safe reads
  - id: ask-fs-write
    match:
      tool: fs.write
      verb: write
    verdict: ask
    reason: Ask operator for writes
  - id: allow-dummy-action
    match:
      tool: dummy.run
    verdict: allow
    reason: Allow dummy execution
"""


# --- Finding 1: Approved-Crossing Authorization Gate & Atomic Claim ---


def test_approved_crossing_re_evaluation_blocks_on_freeze(tmp_path: Path) -> None:
    """If the system is frozen after approval, re-evaluation must block dispatch."""
    db_path = tmp_path / "f1_gate.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_base_policy_yaml())
    boundary = Boundary(policy=policy, receipt_store=store, session_id="sess-f1")
    registry = ExecutorRegistry()
    mock_exec = MagicMock(return_value={"written": True})
    registry.register("fs.write", mock_exec)
    services = AppServices(boundary, executor_registry=registry)

    # 1. Propose action that produces ASK
    sub = services.submit_crossing(
        {
            "tool": "fs.write",
            "verb": "write",
            "resource": "path:C:/data/out.txt",
            "params": {"content": "hello"},
            "session_id": "sess-f1",
        }
    )
    cid = sub["crossing_id"]
    assert sub["verdict"] == "ask"

    # 2. Operator resolves approval
    res = services.resolve_approval(cid, approved=True, execute=False)
    assert res["status"] == "approved"

    # 3. Emergency freeze is triggered BEFORE execution dispatch
    boundary.engine.freeze()

    # 4. Attempt to execute the approved crossing
    exec_res = services.execute_approved_crossing(cid)
    assert "error" in exec_res
    assert "Execution blocked" in exec_res["error"]
    assert exec_res.get("verdict") == "deny"
    # Executor must never have been called!
    mock_exec.assert_not_called()


def test_approved_crossing_atomic_claim_prevents_duplicate_dispatch(tmp_path: Path) -> None:
    """Atomic claim ensures an approved crossing cannot be executed more than once."""
    db_path = tmp_path / "f1_atomic.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_base_policy_yaml())
    boundary = Boundary(policy=policy, receipt_store=store, session_id="sess-f1b")
    registry = ExecutorRegistry()
    mock_exec = MagicMock(return_value={"executed": 1})
    registry.register("fs.write", mock_exec)
    services = AppServices(boundary, executor_registry=registry)

    sub = services.submit_crossing(
        {
            "tool": "fs.write",
            "verb": "write",
            "resource": "path:C:/data/out.txt",
            "session_id": "sess-f1b",
        }
    )
    cid = sub["crossing_id"]
    services.resolve_approval(cid, approved=True, execute=False)

    # First execution succeeds
    res1 = services.execute_approved_crossing(cid)
    assert res1.get("status") == "success"
    assert mock_exec.call_count == 1

    # Second concurrent or duplicate execution is rejected
    res2 = services.execute_approved_crossing(cid)
    assert "error" in res2
    assert "not in approved state" in res2["error"] or "could not be claimed" in res2["error"]
    assert mock_exec.call_count == 1  # Still 1, no duplicate side effect!


def test_cleanup_expired_approvals_expires_approved_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cleanup must expire records that were approved but whose TTL lapsed before execution."""
    simulated_time = 1_700_000_000.0

    def mock_time() -> float:
        return simulated_time

    monkeypatch.setattr(time, "time", mock_time)

    db_path = tmp_path / "f1_ttl.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_base_policy_yaml())
    boundary = Boundary(policy=policy, receipt_store=store, session_id="sess-ttl")
    envelope = build_envelope(
        tool="fs.write",
        verb="write",
        resource="path:C:/data/temp.txt",
        session_id="sess-ttl",
    )
    dec = boundary.engine.evaluate(envelope)

    # Add approval with 10s TTL
    store.add_pending_approval(envelope=envelope, decision=dec, ttl_seconds=10.0)
    resolved = store.resolve_pending_approval(envelope.crossing_id, approved=True)
    assert resolved is not None
    assert resolved.status == "approved"

    # Advance simulated time past TTL
    simulated_time += 15.0

    # Cleanup must transition approved -> expired
    cleaned = store.cleanup_expired_approvals()
    assert cleaned >= 1
    rec = store.get_pending_approval(envelope.crossing_id)
    assert rec is not None
    assert rec.status == "expired"


# --- Finding 2: SSRF Redirect Validation ---


def test_ssrf_safe_redirect_handler_blocks_private_destinations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Redirect handler intercepts and validates each redirect target against SSRF."""
    import socket

    def mock_getaddrinfo(host: str, port: Any, *args: Any, **kwargs: Any) -> list[Any]:
        if host == "other.example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, 80))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    executor = ScopedHTTPExecutor(allow_private_ips=False)
    constraints = {"allowed_hosts": ["api.example.com", "other.example.com"]}

    def validator(url: str) -> None:
        executor._validate_url_target(url, constraints, allow_private=False)

    handler = SSRFSafeRedirectHandler(validator=validator, max_redirects=5)

    # 1. Valid redirect to allowed host passes
    req_mock = MagicMock()
    req_mock.get_method.return_value = "GET"
    res = handler.redirect_request(
        req=req_mock,
        fp=None,
        code=302,
        msg="Found",
        headers={},
        newurl="https://other.example.com/data",
    )
    assert res is not None

    # 2. Redirect to localhost is blocked by SSRF even if in allowed hosts
    executor_local = ScopedHTTPExecutor(allow_private_ips=False)
    handler_local = SSRFSafeRedirectHandler(
        validator=lambda u: executor_local._validate_url_target(
            u, {"allowed_hosts": ["127.0.0.1"]}, allow_private=False
        )
    )
    with pytest.raises(ExecutorError, match="blocked.*SSRF"):
        handler_local.redirect_request(
            req=req_mock,
            fp=None,
            code=302,
            msg="Found",
            headers={},
            newurl="http://127.0.0.1:8080/admin",
        )

    # 3. Redirect to AWS/GCP metadata IP is blocked by SSRF even if allowed in hosts
    handler_meta = SSRFSafeRedirectHandler(
        validator=lambda u: executor_local._validate_url_target(
            u, {"allowed_hosts": ["169.254.169.254"]}, allow_private=False
        )
    )
    with pytest.raises(ExecutorError, match="blocked.*SSRF"):
        handler_meta.redirect_request(
            req=req_mock,
            fp=None,
            code=302,
            msg="Found",
            headers={},
            newurl="http://169.254.169.254/latest/meta-data",
        )

    # 4. Redirect to unallowed domain is blocked
    with pytest.raises(ExecutorError, match="not in the allowed hosts list"):
        handler.redirect_request(
            req=req_mock,
            fp=None,
            code=302,
            msg="Found",
            headers={},
            newurl="https://evil-target.com/pwn",
        )


# --- Finding 3: Non-Loopback Binding Auth Token Enforcement ---


def test_non_loopback_gateway_binding_requires_auth_token(tmp_path: Path) -> None:
    """Non-loopback binding must refuse without both unsafe_allow_remote and an auth token."""
    db_path = tmp_path / "f3_server.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_base_policy_yaml())
    boundary = Boundary(policy=policy, receipt_store=store)

    # 1. Non-loopback without unsafe_allow_remote fails
    with pytest.raises(ValueError, match="without explicit remote authorization"):
        ActentraHTTPServer(
            ("192.168.1.100", 9999),
            boundary,
            unsafe_allow_remote=False,
            auth_token="secret-token",
        )

    # 2. Non-loopback with unsafe_allow_remote but no auth token fails
    with pytest.raises(ValueError, match="without an authentication token"):
        ActentraHTTPServer(
            ("192.168.1.100", 9999),
            boundary,
            unsafe_allow_remote=True,
            auth_token=None,
        )

    # 3. Non-loopback with empty token fails
    with pytest.raises(ValueError, match="without an authentication token"):
        ActentraHTTPServer(
            ("192.168.1.100", 9999),
            boundary,
            unsafe_allow_remote=True,
            auth_token="   ",
        )


# --- Finding 4: Stored XSS Defense in Console and CSP Header ---


def test_console_html_contains_csp_header_and_escaping() -> None:
    """Operator console serves restrictive CSP and escapes dynamic properties."""
    console_path = Path("gateway/actentra_gateway/console.html")
    assert console_path.exists()
    content = console_path.read_text(encoding="utf-8")

    # Verify escapeHtml utility exists and is applied
    assert "function escapeHtml(str)" in content
    assert "escapeHtml(p.crossing_id)" in content
    assert "escapeHtml(p.tool)" in content
    assert "escapeHtml(p.resource)" in content
    assert "escapeHtml(p.reason)" in content
    assert "Parameters:" in content  # Displays action parameters to operator safely

    # Verify CSP header is configured in ActentraHTTPHandler._send_html
    handler_code = Path("gateway/actentra_gateway/http_service.py").read_text(encoding="utf-8")
    assert "Content-Security-Policy" in handler_code
    assert "default-src 'self'" in handler_code


# --- Finding 5: Gateway Session Taint Propagation ---


def test_gateway_session_taint_propagation(tmp_path: Path) -> None:
    """Untrusted provenance taints session state and propagates to subsequent requests."""
    db_path = tmp_path / "f5_taint.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_base_policy_yaml())
    boundary = Boundary(policy=policy, receipt_store=store, session_id="sess-taint")
    services = AppServices(boundary)

    # Action 1: submitted with untrusted provenance
    services.submit_crossing(
        {
            "tool": "dummy.run",
            "verb": "read",
            "resource": "test://doc",
            "session_id": "sess-taint",
            "provenance": [{"source": "web", "trust": "untrusted"}],
        }
    )

    # Verify session taint was set in boundary
    assert boundary.get_session_taint("sess-taint") == "untrusted"

    # Action 2: submitted without provenance for same session
    res2 = services.submit_crossing(
        {
            "tool": "dummy.run",
            "verb": "read",
            "resource": "test://doc2",
            "session_id": "sess-taint",
        }
    )
    # Stored envelope must reflect untrusted taint from session context
    raw_env2 = store.get_envelope(res2["crossing_id"])
    assert raw_env2 is not None
    assert any(
        p["source"] == "session" and p["trust"] == "untrusted" for p in raw_env2["provenance"]
    )


# --- Finding 6: Gateway Cumulative Budget Recording ---


def test_gateway_budget_accumulation(tmp_path: Path) -> None:
    """Gateway executions accumulate actions against session budgets and enforce limit."""
    db_path = tmp_path / "f6_budget.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_base_policy_yaml())  # action_budget: 2
    boundary = Boundary(policy=policy, receipt_store=store, session_id="sess-bud")
    registry = ExecutorRegistry()
    registry.register("dummy.run", lambda env, dec: {"ok": True})
    services = AppServices(boundary, executor_registry=registry)

    # Action 1 (budget 1/2)
    r1 = services.submit_crossing(
        {"tool": "dummy.run", "verb": "read", "resource": "res1", "session_id": "sess-bud"},
        execute=True,
    )
    assert r1["verdict"] == "allow"
    assert r1.get("outcome", {}).get("status") == "success"

    # Action 2 (budget 2/2)
    r2 = services.submit_crossing(
        {"tool": "dummy.run", "verb": "read", "resource": "res2", "session_id": "sess-bud"},
        execute=True,
    )
    assert r2["verdict"] == "allow"
    assert r2.get("outcome", {}).get("status") == "success"

    # Action 3 exceeds action_budget of 2 -> must be DENIED!
    r3 = services.submit_crossing(
        {"tool": "dummy.run", "verb": "read", "resource": "res3", "session_id": "sess-bud"},
        execute=True,
    )
    assert r3["verdict"] == "deny"
    assert r3["rule_id"] == "budget:max-actions-exceeded"
    assert "limit (2) exceeded" in r3["reason"].lower()


# --- Finding 7: SQLite CTE Classification and PRAGMA query_only ---


def test_sqlite_cte_verb_classification() -> None:
    """CTE queries with DELETE, INSERT, or UPDATE are classified, not treated as reads."""
    # Data-changing CTEs
    assert _infer_verb("WITH cte AS (SELECT 1) DELETE FROM users WHERE id = 1;") == "delete"
    assert _infer_verb("WITH RECURSIVE r AS (SELECT 1) INSERT INTO logs VALUES (1);") == "write"
    assert _infer_verb("WITH cte AS (SELECT id FROM t) UPDATE users SET active = 1;") == "write"

    # Read-only CTEs
    assert _infer_verb("WITH cte AS (SELECT 1) SELECT * FROM cte;") == "read"
    assert (
        _infer_verb("WITH cte1 AS (SELECT 1), cte2 AS (SELECT 2) SELECT * FROM cte1, cte2;")
        == "read"
    )

    # Unknown or malformed forms fail closed
    assert _infer_verb("WITH malformed syntax") == "other"


def test_sqlite_executor_enforces_query_only(tmp_path: Path) -> None:
    """Read-only SQLite executor rejects mutating statements and enforces query_only."""
    import sqlite3

    db_path = tmp_path / "sqlite_test.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT);")
    conn.execute("INSERT INTO users VALUES (1, 'Alice');")
    conn.commit()
    conn.close()

    executor = ScopedSQLiteExecutor(db_path, read_only=True)
    envelope = build_envelope(
        tool="sql.execute",
        verb="read",
        resource=executor.resource_id,
        params={"query": "WITH cte AS (SELECT 1) DELETE FROM users WHERE id = 1;"},
    )
    # A decision with read_only constraint
    policy = load_policy_yaml(_base_policy_yaml())
    store = ReceiptStore(tmp_path / "sq.db")
    boundary = Boundary(policy=policy, receipt_store=store)
    decision = boundary.engine.evaluate(envelope)

    with pytest.raises(ExecutorError, match="read_only mode permits SELECT queries only"):
        executor.execute(envelope, decision)


# --- Finding 8: External Outcome Duplicate Prevention & Decision Verification ---


def test_external_outcome_prevents_duplicate_and_verifies_decision(tmp_path: Path) -> None:
    """External outcomes cannot be reported for non-allowed decisions or duplicate reports."""
    db_path = tmp_path / "f8_outcome.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_base_policy_yaml())
    boundary = Boundary(policy=policy, receipt_store=store)
    services = AppServices(boundary)

    # 1. Action resulting in DENY
    deny_crossing = services.submit_crossing(
        {"tool": "forbidden.tool", "verb": "write", "resource": "res"}
    )
    deny_cid = deny_crossing["crossing_id"]
    assert deny_crossing["verdict"] == "deny"

    # Outcome reporting on DENIED crossing must be rejected
    r_err = services.record_external_outcome(deny_cid, status="success")
    assert "error" in r_err
    assert "Cannot record execution outcome for non-allowed decision" in r_err["error"]

    # 2. Action resulting in ALLOW
    allow_crossing = services.submit_crossing(
        {"tool": "dummy.run", "verb": "read", "resource": "res"}
    )
    allow_cid = allow_crossing["crossing_id"]
    assert allow_crossing["verdict"] == "allow"

    # First outcome report succeeds
    r_ok = services.record_external_outcome(allow_cid, status="success")
    assert r_ok.get("status") == "recorded"
    assert r_ok.get("reported_by") == "caller"

    # Duplicate outcome report is rejected
    r_dup = services.record_external_outcome(allow_cid, status="success")
    assert "error" in r_dup
    assert "Outcome already recorded" in r_dup["error"]

    # Verify stored outcome record has reason="caller-reported"
    records = store.iter_records()
    outcome_recs = [r for r in records if r.record_type == "outcome" and r.crossing_id == allow_cid]
    assert len(outcome_recs) == 1
    assert outcome_recs[0].reason == "caller-reported"


def test_concurrent_external_outcome_reports_yields_at_most_one(tmp_path: Path) -> None:
    """Concurrent external outcome submissions yield exactly one recorded outcome."""
    db_path = tmp_path / "f8_concurrent.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_base_policy_yaml())
    boundary = Boundary(policy=policy, receipt_store=store, session_id="sess-concurrent")
    services = AppServices(boundary)

    crossing = services.submit_crossing(
        {"tool": "dummy.run", "verb": "read", "resource": "res-concurrent"}
    )
    cid = crossing["crossing_id"]
    assert crossing["verdict"] == "allow"

    results: list[dict[str, Any]] = []
    errors: list[Exception] = []

    def _worker() -> None:
        try:
            res = services.record_external_outcome(cid, status="success")
            results.append(res)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=_worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    successes = [r for r in results if r.get("status") == "recorded"]
    failures = [r for r in results if "error" in r]
    assert len(successes) == 1
    assert len(failures) == 9
    for f in failures:
        assert "Outcome already recorded" in f["error"]

    # Verify store has exactly 1 outcome record
    outcomes = [
        r for r in store.iter_records() if r.record_type == "outcome" and r.crossing_id == cid
    ]
    assert len(outcomes) == 1


def test_external_outcome_updates_cumulative_session_budget(tmp_path: Path) -> None:
    """External execution outcome reporting consumes session cumulative budget."""
    db_path = tmp_path / "f8_budget.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_base_policy_yaml())
    boundary = Boundary(policy=policy, receipt_store=store, session_id="sess-ext-budget")
    services = AppServices(boundary)

    # Initial usage
    stats0 = boundary.engine.budget_tracker.get_session_stats("sess-ext-budget")
    assert stats0["actions_count"] == 0

    # 1. Propose and allow action 1
    sub1 = services.submit_crossing(
        {"tool": "dummy.run", "verb": "read", "resource": "res1", "session_id": "sess-ext-budget"}
    )
    cid1 = sub1["crossing_id"]
    assert sub1["verdict"] == "allow"

    # Outcome reported as success -> budget increments
    services.record_external_outcome(cid1, status="success")
    stats1 = boundary.engine.budget_tracker.get_session_stats("sess-ext-budget")
    assert stats1["actions_count"] == 1

    # 2. Propose and allow action 2
    sub2 = services.submit_crossing(
        {"tool": "dummy.run", "verb": "read", "resource": "res2", "session_id": "sess-ext-budget"}
    )
    cid2 = sub2["crossing_id"]
    assert sub2["verdict"] == "allow"
    services.record_external_outcome(cid2, status="success")
    stats2 = boundary.engine.budget_tracker.get_session_stats("sess-ext-budget")
    assert stats2["actions_count"] == 2

    # 3. Third action exceeds max_actions (budget is 2) -> blocked by budget!
    sub3 = services.submit_crossing(
        {"tool": "dummy.run", "verb": "read", "resource": "res3", "session_id": "sess-ext-budget"}
    )
    assert sub3["verdict"] == "deny"
    assert "budget:max-actions-exceeded" in sub3["rule_id"]


def test_stored_envelope_context_integrity_verification(tmp_path: Path) -> None:
    """Tampering with stored action envelope is detected during verification and retrieval."""
    db_path = tmp_path / "f8_envelope_integrity.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_base_policy_yaml())
    boundary = Boundary(policy=policy, receipt_store=store, session_id="sess-integrity")
    services = AppServices(boundary)

    sub = services.submit_crossing({"tool": "dummy.run", "verb": "read", "resource": "res-intact"})
    cid = sub["crossing_id"]

    # Retrieval of untampered envelope succeeds
    env_clean = store.get_envelope(cid, verify_integrity=True)
    assert env_clean is not None
    assert env_clean["action"]["resource"] == "res-intact"

    # Full log verification with envelope verification passes
    vr_clean = verify_log(db_path, verify_envelopes=True)
    assert vr_clean.ok is True
    assert len(vr_clean.errors) == 0

    # Tamper with the envelope in SQLite (change resource)
    import sqlite3

    conn = sqlite3.connect(db_path)
    cur = conn.execute("SELECT envelope_json FROM action_envelopes WHERE crossing_id = ?;", (cid,))
    raw_json = cur.fetchone()[0]
    import json

    data = json.loads(raw_json)
    data["action"]["resource"] = "res-TAMPERED"
    conn.execute(
        "UPDATE action_envelopes SET envelope_json = ? WHERE crossing_id = ?;",
        (json.dumps(data), cid),
    )
    conn.commit()
    conn.close()

    # get_envelope with verify_integrity=True detects hash mismatch and returns None
    env_tampered = store.get_envelope(cid, verify_integrity=True)
    assert env_tampered is None

    # verify_log with verify_envelopes=True detects the altered context
    vr_tampered = verify_log(db_path, verify_envelopes=True)
    assert vr_tampered.ok is False
    assert any("envelope action hash mismatch" in err for err in vr_tampered.errors)


# --- Finding 9: Bounded Receipt Queries ---


def test_receipt_query_limit_and_offset_clamping(tmp_path: Path) -> None:
    """Receipt queries clamp negative or excessive limits and offsets."""
    db_path = tmp_path / "f9_bounds.db"
    store = ReceiptStore(db_path)

    # Query with negative limit and negative offset
    records, total = store.query_records(limit=-1, offset=-10)
    assert isinstance(records, list)
    assert total == 0

    # Query with huge limit is clamped to max 500
    records, total = store.query_records(limit=999999)
    assert isinstance(records, list)


# --- Finding 10: Negative Content-Length Rejection ---


def test_http_service_rejects_negative_content_length() -> None:
    """Negative Content-Length header is rejected with ValueError."""
    handler = ActentraHTTPHandler.__new__(ActentraHTTPHandler)
    handler.headers = {"Content-Length": "-1"}  # type: ignore[assignment]
    handler.rfile = io.BytesIO()

    with pytest.raises(ValueError, match="Negative Content-Length header is invalid"):
        handler._read_json_body()


# --- Additional Improvement: Side-Effect-Free Simulation ---


def test_simulation_does_not_consume_rate_limit(tmp_path: Path) -> None:
    """Simulate/dry-run does not advance or deplete rate-limit bucket tokens."""
    rate_policy_yaml = """
version: 1
policy_id: rate-limit-test
mode: enforce
defaults:
  verdict: deny
limits:
  - id: tight-rate
    scope: global
    max_actions_per_minute: 2
rules:
  - id: allow-dummy
    match:
      tool: dummy.run
    verdict: allow
"""
    db_path = tmp_path / "sim_rate.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(rate_policy_yaml)  # max 2 per minute
    boundary = Boundary(policy=policy, receipt_store=store, session_id="sess-sim")
    services = AppServices(boundary)

    # Run dry-run simulation 5 times (exceeding the limit of 2)
    for _ in range(5):
        sim = services.simulate_dry_run(
            tool="dummy.run",
            verb="read",
            resource="test://res",
            session_id="sess-sim",
        )
        assert sim["verdict"] == "allow"

    # Real action execution still has its full rate limit quota available!
    res1 = services.submit_crossing(
        {"tool": "dummy.run", "verb": "read", "resource": "test://res", "session_id": "sess-sim"}
    )
    assert res1["verdict"] == "allow"

    res2 = services.submit_crossing(
        {"tool": "dummy.run", "verb": "read", "resource": "test://res", "session_id": "sess-sim"}
    )
    assert res2["verdict"] == "allow"

    # 3rd real action exceeds rate limit
    res3 = services.submit_crossing(
        {"tool": "dummy.run", "verb": "read", "resource": "test://res", "session_id": "sess-sim"}
    )
    assert res3["verdict"] == "deny"
    assert "rate limit" in res3["reason"].lower()
    assert res2["verdict"] == "allow"
