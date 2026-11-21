"""Security regression tests for Finding 05: Unbound external outcome reporting.

Verifies:
- T-05: Record allowed crossing.
- T-05: Reject outcome reporting before claim issuance (missing claim_id).
- T-05: Accept outcome once only from the exact authenticated executor principal.
- T-05: Reject claim reuse / replay attempts (one-time consumption).
- T-05: Reject cross-executor claim spoofing (executor A's claim cannot be used by executor B).
- Reject outcome reporting with expired execution claims.
- Prevent claiming crossings with non-allowed verdicts or already executed status.
- End-to-end HTTP gateway validation for /claim and /outcome endpoints.
- Separate caller-reported evidence from externally verified evidence.
"""

from __future__ import annotations

import io
import json
import time
from http import HTTPStatus
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from actentra.boundary import Boundary
from actentra_core.identity import CallerContext, PrincipalType
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_gateway.http_service import ActentraHTTPHandler
from actentra_gateway.services import AppServices, ExecutorRegistry

_POLICY_YAML = """\
version: 1
policy_id: test-external-outcomes
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-compute
    match: { tool: "compute.*", verb: "exec" }
    verdict: allow
  - id: ask-admin
    match: { tool: "admin.*", verb: "admin" }
    verdict: ask
"""


@pytest.fixture
def service_env(tmp_path: Path) -> tuple[AppServices, ReceiptStore]:
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_POLICY_YAML)
    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        agent_id="agent-worker",
    )
    services = AppServices(boundary, executor_registry=ExecutorRegistry())
    return services, store


def _propose_allowed_crossing(services: AppServices, tool: str = "compute.add") -> str:
    """Helper to propose an allowed crossing and return its crossing_id."""
    raw_envelope = {
        "tool": tool,
        "verb": "exec",
        "resource": "tool:calc",
        "params": {"a": 1, "b": 2},
        "session_id": "sess-outcomes",
        "agent_id": "agent-worker",
        "agent": {"id": "agent-worker"},
    }
    resp = services.submit_crossing(raw_envelope, execute=False)
    assert resp["verdict"] == "allow"
    return str(resp["crossing_id"])


def test_outcome_rejected_without_claim(service_env: tuple[AppServices, ReceiptStore]) -> None:
    """T-05: Submitting outcome before claim issuance is strictly rejected."""
    services, store = service_env
    cid = _propose_allowed_crossing(services)

    executor_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="executor-worker-1",
        authenticated=True,
        trust_domain="cloud_worker",
        scopes=("crossings:claim", "crossings:outcome"),
        allowed_agents=("agent-worker",),
    )

    # Attempt to report outcome without claim_id
    res = services.record_external_outcome(
        cid,
        status="success",
        claim_id=None,
        caller_context=executor_ctx,
    )
    assert "error" in res
    assert res.get("code") == "claim_required"
    assert "claim_id" in res["error"]

    # Assert no outcome was recorded
    assert store.get_outcome_receipt(cid) is None


def test_claim_issuance_and_successful_outcome_binding(
    service_env: tuple[AppServices, ReceiptStore],
) -> None:
    """T-05: Allowed crossing is claimed by executor and outcome recorded once."""
    services, store = service_env
    cid = _propose_allowed_crossing(services)

    executor_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="executor-worker-1",
        authenticated=True,
        trust_domain="cloud_worker",
        scopes=("crossings:claim", "crossings:outcome"),
        allowed_agents=("agent-worker",),
    )

    # 1. Issue one-time execution claim
    claim_resp = services.claim_crossing_for_execution(cid, caller_context=executor_ctx)
    assert "claim_id" in claim_resp
    assert claim_resp["crossing_id"] == cid
    assert claim_resp["executor_principal_id"] == "executor-worker-1"
    assert claim_resp["status"] == "issued"
    claim_id = claim_resp["claim_id"]

    # 2. Report outcome using valid claim
    out_resp = services.record_external_outcome(
        cid,
        status="success",
        claim_id=claim_id,
        result_hash="sha256:" + ("1" * 64),
        caller_context=executor_ctx,
    )
    assert out_resp["status"] == "recorded"
    assert out_resp["claim_id"] == claim_id

    # 3. Verify outcome receipt was committed with caller_reported evidence
    out_rec = store.get_outcome_receipt(cid)
    assert out_rec is not None
    assert out_rec.status == "success"
    assert out_rec.evidence_status == "caller_reported"

    # 4. Verify claim status transitioned to consumed
    stored_claim = store.get_execution_claim(claim_id)
    assert stored_claim is not None
    assert stored_claim.status == "consumed"
    assert stored_claim.consumed_at is not None

    # 5. Verify EvidenceRecord tier is CALLER_REPORTED, NOT externally_verified
    ev_list = store.list_evidence(tier="caller_reported")
    assert len(ev_list) == 1
    assert ev_list[0].collector == "executor:executor-worker-1"
    assert ev_list[0].details["claim_id"] == claim_id

    ext_ev = store.list_evidence(tier="externally_verified")
    assert len(ext_ev) == 0


def test_claim_replay_rejected(service_env: tuple[AppServices, ReceiptStore]) -> None:
    """T-05: Replaying an already-consumed claim is rejected."""
    services, store = service_env
    cid = _propose_allowed_crossing(services)

    executor_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="executor-worker-1",
        authenticated=True,
        trust_domain="cloud_worker",
        scopes=("crossings:claim", "crossings:outcome"),
        allowed_agents=("agent-worker",),
    )

    claim_resp = services.claim_crossing_for_execution(cid, caller_context=executor_ctx)
    claim_id = claim_resp["claim_id"]

    # First consumption succeeds
    res1 = services.record_external_outcome(
        cid,
        status="success",
        claim_id=claim_id,
        caller_context=executor_ctx,
    )
    assert res1["status"] == "recorded"

    # Replay attempt with same claim_id fails
    res2 = services.record_external_outcome(
        cid,
        status="success",
        claim_id=claim_id,
        caller_context=executor_ctx,
    )
    assert "error" in res2
    assert "already been consumed" in res2["error"] or "conflict" in res2.get("code", "")


def test_cross_executor_claim_spoofing_rejected(
    service_env: tuple[AppServices, ReceiptStore],
) -> None:
    """T-05: Executor B cannot use an execution claim issued to Executor A."""
    services, store = service_env
    cid = _propose_allowed_crossing(services)

    executor_a = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="executor-alice",
        authenticated=True,
        trust_domain="cluster_a",
        scopes=("crossings:claim", "crossings:outcome"),
        allowed_agents=("agent-worker",),
    )
    executor_b = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="executor-bob",
        authenticated=True,
        trust_domain="cluster_b",
        scopes=("crossings:claim", "crossings:outcome"),
        allowed_agents=("agent-worker",),
    )

    # 1. Executor Alice claims the crossing
    claim_resp = services.claim_crossing_for_execution(cid, caller_context=executor_a)
    claim_id = claim_resp["claim_id"]

    # 2. Executor Bob intercepts or guesses claim_id and attempts to report outcome
    res_b = services.record_external_outcome(
        cid,
        status="success",
        claim_id=claim_id,
        caller_context=executor_b,
    )
    assert "error" in res_b
    assert res_b.get("code") == "forbidden"
    assert "issued to executor 'executor-alice'" in res_b["error"]
    assert "executor-bob" in res_b["error"]

    # Assert outcome was NOT recorded
    assert store.get_outcome_receipt(cid) is None

    # 3. Legitimate Executor Alice then reports outcome -> succeeds!
    res_a = services.record_external_outcome(
        cid,
        status="success",
        claim_id=claim_id,
        caller_context=executor_a,
    )
    assert res_a["status"] == "recorded"
    assert store.get_outcome_receipt(cid) is not None


def test_expired_claim_rejected(service_env: tuple[AppServices, ReceiptStore]) -> None:
    """Execution claims past their TTL are rejected as expired."""
    services, store = service_env
    cid = _propose_allowed_crossing(services)

    executor_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="executor-slow",
        authenticated=True,
        trust_domain="cluster",
        scopes=("crossings:claim", "crossings:outcome"),
        allowed_agents=("agent-worker",),
    )

    # Issue claim with very short TTL
    claim_resp = services.claim_crossing_for_execution(
        cid,
        caller_context=executor_ctx,
        ttl_seconds=0.01,
    )
    claim_id = claim_resp["claim_id"]

    # Wait for expiration
    time.sleep(0.05)

    res = services.record_external_outcome(
        cid,
        status="success",
        claim_id=claim_id,
        caller_context=executor_ctx,
    )
    assert "error" in res
    assert "expired" in res["error"].lower()
    assert res.get("code") == "expired"


def test_cannot_claim_disallowed_crossing(service_env: tuple[AppServices, ReceiptStore]) -> None:
    """Non-allowed (ASK/DENY) crossings cannot be claimed without approval."""
    services, _ = service_env
    raw_envelope = {
        "tool": "admin.delete",
        "verb": "admin",
        "resource": "server:main",
        "session_id": "sess-ask",
        "agent": {"id": "agent-worker"},
    }
    resp = services.submit_crossing(raw_envelope, execute=False)
    assert resp["verdict"] == "ask"
    cid = str(resp["crossing_id"])

    executor_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="executor-1",
        authenticated=True,
        trust_domain="cluster",
        scopes=("crossings:claim", "crossings:outcome"),
        allowed_agents=("agent-worker",),
    )

    claim_res = services.claim_crossing_for_execution(cid, caller_context=executor_ctx)
    assert "error" in claim_res
    assert claim_res.get("code") == "not_permitted"


def _dispatch_http(
    services: AppServices,
    method: str,
    path: str,
    data: Any = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any]:
    handler = ActentraHTTPHandler.__new__(ActentraHTTPHandler)
    server_mock = MagicMock()
    server_mock.services = services
    server_mock.boundary = services.boundary
    server_mock.auth_token = None
    server_mock.token_principals = None
    handler.server = server_mock
    handler.request_version = "HTTP/1.1"
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.close_connection = True
    handler.path = path
    handler.wfile = io.BytesIO()

    body_bytes = json.dumps(data).encode("utf-8") if data is not None else b""
    hdrs = {"Content-Length": str(len(body_bytes)), "Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    handler.headers = hdrs  # type: ignore[assignment]
    handler.rfile = io.BytesIO(body_bytes)

    if method == "POST":
        handler.do_POST()
    elif method == "GET":
        handler.do_GET()
    else:
        raise ValueError(f"Unsupported method {method}")

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


def test_http_gateway_claim_and_outcome_end_to_end(tmp_path: Path) -> None:
    """End-to-end HTTP REST API verification of claim issuance and outcome binding."""
    db_path = tmp_path / "gateway.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_POLICY_YAML)
    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        agent_id="agent-worker",
    )
    services = AppServices(boundary, executor_registry=ExecutorRegistry())

    # 1. Propose allowed crossing
    propose_body = {
        "tool": "compute.add",
        "verb": "exec",
        "resource": "tool:calc",
        "params": {"x": 10},
        "session_id": "sess-http",
        "agent_id": "agent-worker",
        "agent": {"id": "agent-worker"},
    }
    s1, p_data = _dispatch_http(services, "POST", "/v1/crossings", data=propose_body)
    assert s1 == HTTPStatus.OK
    cid = p_data["crossing_id"]

    # 2. Attempt outcome reporting without claim -> 400 Bad Request
    s2, r2_data = _dispatch_http(
        services,
        "POST",
        f"/v1/crossings/{cid}/outcome",
        data={"status": "success"},
    )
    assert s2 == HTTPStatus.BAD_REQUEST
    assert r2_data.get("code") == "claim_required"

    # 3. Issue execution claim via /claim endpoint
    s3, claim_data = _dispatch_http(
        services,
        "POST",
        f"/v1/crossings/{cid}/claim",
        data={},
        headers={"X-Actentra-Identity": "executor-primary"},
    )
    assert s3 == HTTPStatus.OK
    assert "claim_id" in claim_data
    claim_id = claim_data["claim_id"]

    # 4. Attempt outcome reporting with mismatched executor identity -> 403 Forbidden
    s4, r4_data = _dispatch_http(
        services,
        "POST",
        f"/v1/crossings/{cid}/outcome",
        data={"status": "success", "claim_id": claim_id},
        headers={"X-Actentra-Identity": "executor-imposter"},
    )
    assert s4 == HTTPStatus.FORBIDDEN
    assert "executor" in str(r4_data.get("error", "")).lower()

    # 5. Legitimate outcome reporting with matching executor -> 200 OK
    s5, r5_data = _dispatch_http(
        services,
        "POST",
        f"/v1/crossings/{cid}/outcome",
        data={"status": "success", "claim_id": claim_id},
        headers={"X-Actentra-Identity": "executor-primary"},
    )
    assert s5 == HTTPStatus.OK
    assert r5_data.get("status") == "recorded"

    # 6. Replay attempt with same claim_id -> 409 Conflict
    s6, _ = _dispatch_http(
        services,
        "POST",
        f"/v1/crossings/{cid}/outcome",
        data={"status": "success", "claim_id": claim_id},
        headers={"X-Actentra-Identity": "executor-primary"},
    )
    assert s6 == HTTPStatus.CONFLICT
