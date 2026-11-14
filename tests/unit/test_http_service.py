"""Unit and HTTP client integration tests for the Actentra Gateway HTTP service."""

from __future__ import annotations

import io
import json
import urllib.request
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from actentra import Boundary
from actentra_core.envelope import build_envelope
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_gateway.http_service import ActentraHTTPHandler
from actentra_gateway.services import AppServices


def _request_json(
    url: str,
    method: str = "GET",
    data: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    encoded = json.dumps(data).encode("utf-8") if data is not None else None
    headers = {"Content-Type": "application/json"} if encoded is not None else {}
    req = urllib.request.Request(url, data=encoded, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            content = resp.read().decode("utf-8")
            return resp.status, json.loads(content)
    except urllib.error.HTTPError as exc:
        err_content = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(err_content)
        except Exception:
            return exc.code, err_content
    except (OSError, urllib.error.URLError) as exc:
        if "10013" in str(exc) or "forbidden" in str(exc).lower():
            pytest.skip(f"Loopback socket access restricted by sandbox environment: {exc}")
        raise


def test_http_service_endpoints_and_web_approval(tmp_path: Path) -> None:
    db_path = tmp_path / "gateway.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(
        """
version: 1
policy_id: gateway-test-policy
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-calc
    match: { tool: calc, verb: read }
    verdict: allow
  - id: ask-deploy
    match: { tool: deploy, verb: write }
    verdict: ask
    reason: "Production deploy requires approval"
"""
    )
    boundary = Boundary(policy=policy, receipt_store=store, session_id="http-test-session")
    services = AppServices(boundary)

    # 1. GET /health
    code, health = _dispatch_handler(services, "/health")
    assert code == 200
    assert health["status"] == "ok"
    assert health["policy_id"] == "gateway-test-policy"
    assert health["frozen"] is False

    # 2. POST /v1/crossings (Allowed action)
    code, dec1 = _dispatch_handler(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "calc",
            "verb": "read",
            "resource": "tool:calc",
            "params": {"a": 1, "b": 2},
            "session_id": "s1",
        },
    )
    assert code == 200
    assert dec1["verdict"] == "allow"
    assert dec1["rule_id"] == "allow-calc"
    cid1 = dec1["crossing_id"]
    assert cid1

    # 3. POST /v1/crossings (Denied by default)
    code, dec2 = _dispatch_handler(
        services,
        "/v1/crossings",
        method="POST",
        data={"tool": "destroy_all", "verb": "delete", "resource": "res:1"},
    )
    assert code == 200
    assert dec2["verdict"] == "deny"
    assert dec2["rule_id"] == "default"

    # 4. POST /v1/crossings (ASK - pending human approval)
    code, dec3 = _dispatch_handler(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "deploy",
            "verb": "write",
            "resource": "env:production",
            "session_id": "s-deploy",
        },
    )
    assert code == 200
    assert dec3["verdict"] == "ask"
    assert dec3["rule_id"] == "ask-deploy"
    cid_deploy = dec3["crossing_id"]

    # 5. GET /v1/crossings/pending
    code, pending = _dispatch_handler(services, "/v1/crossings/pending")
    assert code == 200
    assert len(pending) == 1
    assert pending[0]["crossing_id"] == cid_deploy
    assert pending[0]["tool"] == "deploy"

    # 6. POST /v1/crossings/{id}/approve (Approve pending crossing)
    code, app_res = _dispatch_handler(
        services,
        f"/v1/crossings/{cid_deploy}/approve",
        method="POST",
        data={"approved": True},
    )
    assert code == 200
    assert app_res["status"] == "approved"

    # Pending list should now be empty
    _, pending_after = _dispatch_handler(services, "/v1/crossings/pending")
    assert len(pending_after) == 0

    # Now boundary has approval grant for that session & canonical hash
    env_check = build_envelope(
        tool="deploy",
        verb="write",
        resource="env:production",
        session_id="s-deploy",
        agent_id="http-client",
    )
    assert boundary._has_valid_approval(env_check) is True

    # 7. GET /v1/verify
    code, vr_res = _dispatch_handler(services, "/v1/verify")
    assert code == 200
    assert vr_res["ok"] is True
    assert vr_res["total_records"] == 3  # 3 decisions logged

    # 8. GET /v1/receipts
    code, receipts = _dispatch_handler(services, "/v1/receipts")
    assert code == 200
    assert len(receipts) == 3

    # 9. POST /v1/freeze (Kill switch)
    code, freeze_res = _dispatch_handler(services, "/v1/freeze", method="POST")
    assert code == 200
    assert freeze_res["frozen"] is True
    assert boundary.engine.frozen is True

    # Unfreeze
    code, unfreeze_res = _dispatch_handler(services, "/v1/unfreeze", method="POST")
    assert code == 200
    assert unfreeze_res["frozen"] is False
    assert boundary.engine.frozen is False

    # 10. GET /ui (Operator console HTML)
    code, ui_html = _dispatch_handler(services, "/ui")
    assert code == 200
    assert "<!DOCTYPE html>" in str(ui_html)
    assert "Operator Console" in str(ui_html)
    assert "Pending Human Approvals" in str(ui_html)


def _dispatch_handler(
    services: AppServices,
    path: str,
    method: str = "GET",
    data: dict[str, Any] | bytes | str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any]:
    handler = ActentraHTTPHandler.__new__(ActentraHTTPHandler)
    server_mock = MagicMock()
    server_mock.services = services
    server_mock.auth_token = None
    server_mock.boundary = services.boundary
    handler.server = server_mock
    handler.request_version = "HTTP/1.1"
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.close_connection = True
    handler.path = path
    handler.wfile = io.BytesIO()

    if data is not None:
        if isinstance(data, bytes):
            body_bytes = data
        elif isinstance(data, str):
            body_bytes = data.encode("utf-8")
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


def test_http_approval_strict_fail_closed_and_outcomes(tmp_path: Path) -> None:
    """Test strict fail-closed validation for approvals and atomic outcome endpoints."""
    db_path = tmp_path / "strict_http.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(
        """
version: 1
policy_id: strict-http-policy
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-calc
    match: { tool: calc, verb: read }
    verdict: allow
  - id: ask-transfer
    match: { tool: bank.transfer, verb: write }
    verdict: ask
    reason: "Transfer requires human approval"
"""
    )
    boundary = Boundary(policy=policy, receipt_store=store, session_id="s-strict")
    services = AppServices(boundary)

    # Submit an ASK crossing
    code, dec = _dispatch_handler(
        services,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "bank.transfer",
            "verb": "write",
            "resource": "account:999",
            "params": {"amount": 100},
            "session_id": "s-strict",
        },
    )
    assert code == 200
    assert dec["verdict"] == "ask"
    cid = dec["crossing_id"]

    # Negative Case 1: Empty JSON body must reject with 400
    code, err = _dispatch_handler(
        services,
        f"/v1/crossings/{cid}/approve",
        method="POST",
        data={},
    )
    assert code == 400
    assert "Missing required field 'approved'" in str(err)

    # Negative Case 2: String-valued approved ("true") must reject with 400
    code, err = _dispatch_handler(
        services,
        f"/v1/crossings/{cid}/approve",
        method="POST",
        data={"approved": "true"},
    )
    assert code == 400
    assert "Field 'approved' must be a JSON boolean" in str(err)

    # Negative Case 3: Integer-valued approved (1) must reject with 400
    code, err = _dispatch_handler(
        services,
        f"/v1/crossings/{cid}/approve",
        method="POST",
        data={"approved": 1},
    )
    assert code == 400
    assert "Field 'approved' must be a JSON boolean" in str(err)

    # Negative Case 4: Non-boolean execute field must reject with 400
    code, err = _dispatch_handler(
        services,
        f"/v1/crossings/{cid}/approve",
        method="POST",
        data={"approved": True, "execute": "yes"},
    )
    assert code == 400
    assert "Field 'execute' must be a JSON boolean" in str(err)

    # Negative Case 5: Raw malformed body must reject with 400
    code, err = _dispatch_handler(
        services,
        f"/v1/crossings/{cid}/approve",
        method="POST",
        data=b"not valid json",
    )
    assert code == 400

    # Positive Case: Explicit False rejection works
    code, res_reject = _dispatch_handler(
        services,
        f"/v1/crossings/{cid}/approve",
        method="POST",
        data={"approved": False},
    )
    assert code == 200
    assert res_reject["status"] == "rejected"

    # External outcome endpoints
    # 1. Allowed crossing
    code, allow_dec = _dispatch_handler(
        services,
        "/v1/crossings",
        method="POST",
        data={"tool": "calc", "verb": "read", "resource": "tool:calc"},
    )
    assert code == 200
    allow_cid = allow_dec["crossing_id"]

    # 2. Record outcome on allowed crossing
    code, out_res = _dispatch_handler(
        services,
        f"/v1/crossings/{allow_cid}/outcome",
        method="POST",
        data={"status": "success", "result_hash": "sha256:abcd"},
    )
    assert code == 200
    assert out_res["status"] == "recorded"
    assert out_res["reported_by"] == "caller"

    # 3. Duplicate outcome must reject with 409 Conflict
    code, dup_res = _dispatch_handler(
        services,
        f"/v1/crossings/{allow_cid}/outcome",
        method="POST",
        data={"status": "success"},
    )
    assert code == 409
    assert "Outcome already recorded" in str(dup_res)

    # 4. Outcome on non-existent crossing must reject with 404 Not Found
    code, nf_res = _dispatch_handler(
        services,
        "/v1/crossings/nonexistent-crossing-id/outcome",
        method="POST",
        data={"status": "success"},
    )
    assert code == 404
