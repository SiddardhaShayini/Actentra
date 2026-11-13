"""Unit and HTTP client integration tests for the Actentra Gateway HTTP service."""

from __future__ import annotations

import json
import threading
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from actentra import Boundary
from actentra_core.envelope import build_envelope
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_gateway.http_service import create_gateway_server


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
    server = create_gateway_server(boundary, host="127.0.0.1", port=0)
    port = server.server_port

    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()

    base_url = f"http://127.0.0.1:{port}"

    try:
        # 1. GET /health
        code, health = _request_json(f"{base_url}/health")
        assert code == 200
        assert health["status"] == "ok"
        assert health["policy_id"] == "gateway-test-policy"
        assert health["frozen"] is False

        # 2. POST /v1/crossings (Allowed action)
        code, dec1 = _request_json(
            f"{base_url}/v1/crossings",
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
        code, dec2 = _request_json(
            f"{base_url}/v1/crossings",
            method="POST",
            data={"tool": "destroy_all", "verb": "delete", "resource": "res:1"},
        )
        assert code == 200
        assert dec2["verdict"] == "deny"
        assert dec2["rule_id"] == "default"

        # 4. POST /v1/crossings (ASK - pending human approval)
        code, dec3 = _request_json(
            f"{base_url}/v1/crossings",
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
        code, pending = _request_json(f"{base_url}/v1/crossings/pending")
        assert code == 200
        assert len(pending) == 1
        assert pending[0]["crossing_id"] == cid_deploy
        assert pending[0]["tool"] == "deploy"

        # 6. POST /v1/crossings/{id}/approve (Approve pending crossing)
        code, app_res = _request_json(
            f"{base_url}/v1/crossings/{cid_deploy}/approve",
            method="POST",
            data={"approved": True},
        )
        assert code == 200
        assert app_res["status"] == "approved"

        # Pending list should now be empty
        _, pending_after = _request_json(f"{base_url}/v1/crossings/pending")
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
        code, vr_res = _request_json(f"{base_url}/v1/verify")
        assert code == 200
        assert vr_res["ok"] is True
        assert vr_res["total_records"] == 3  # 3 decisions logged

        # 8. GET /v1/receipts
        code, receipts = _request_json(f"{base_url}/v1/receipts")
        assert code == 200
        assert len(receipts) == 3

        # 9. POST /v1/freeze (Kill switch)
        code, freeze_res = _request_json(f"{base_url}/v1/freeze", method="POST")
        assert code == 200
        assert freeze_res["frozen"] is True
        assert boundary.engine.frozen is True

        # Unfreeze
        code, unfreeze_res = _request_json(f"{base_url}/v1/unfreeze", method="POST")
        assert code == 200
        assert unfreeze_res["frozen"] is False
        assert boundary.engine.frozen is False

        # 10. GET /ui (Operator console HTML)
        req_ui = urllib.request.Request(f"{base_url}/ui")
        with urllib.request.urlopen(req_ui) as ui_resp:
            ui_html = ui_resp.read().decode("utf-8")
            assert "<!DOCTYPE html>" in ui_html
            assert "Operator Console" in ui_html
            assert "Pending Human Approvals" in ui_html
    finally:
        server.shutdown()
        server.server_close()
