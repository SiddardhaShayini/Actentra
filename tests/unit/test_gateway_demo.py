"""Tests for the Phase 1 restart-safe HTTP gateway demonstration."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from typer.testing import CliRunner

from actentra.boundary import Boundary
from actentra_cli.main import app
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_gateway.demo import run_gateway_demonstration
from actentra_gateway.http_service import ActentraHTTPHandler
from actentra_gateway.services import AppServices, ExecutorRegistry

runner = CliRunner()


def _dispatch_handler(
    services: AppServices,
    path: str,
    method: str = "GET",
    data: Any = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any]:
    """Helper to dispatch HTTP requests through ActentraHTTPHandler with mock streams."""
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

    hdrs = {
        "Content-Length": str(len(body_bytes)),
        "Content-Type": "application/json",
        "Origin": "http://127.0.0.1:8080",
    }
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


def test_gateway_demonstration_direct(tmp_path: Path) -> None:
    """Test the complete gateway demonstration function end-to-end."""
    ws = tmp_path / "ws"
    db = tmp_path / "receipts.db"
    res = run_gateway_demonstration(workspace_dir=ws, db_path=db, verbose=False)
    assert res.ok
    assert res.steps_executed >= 10
    assert res.verification.ok
    assert res.verification.total_records >= 7
    assert res.summary["protected_file_deleted"] is True


def test_cli_demo_gateway_command(tmp_path: Path) -> None:
    """Test `actentra demo-gateway` and `actentra demo --gateway` via Typer CLI runner."""
    ws = tmp_path / "cli_ws"
    db = tmp_path / "cli_receipts.db"

    # Test actentra demo-gateway
    res1 = runner.invoke(app, ["demo-gateway", "--workspace", str(ws), "--db", str(db)])
    assert res1.exit_code == 0
    assert "Gateway demonstration completed successfully" in res1.output
    assert "Log Verification: ok=True" in res1.output

    # Test actentra demo --gateway
    res2 = runner.invoke(app, ["demo", "--gateway"])
    assert res2.exit_code == 0
    assert "Gateway demonstration completed successfully" in res2.output


def test_gateway_demo_over_http_handler(tmp_path: Path) -> None:
    """Test the complete restart-safe lifecycle through ActentraHTTPHandler."""
    ws = tmp_path / "http_ws"
    ws.mkdir(parents=True, exist_ok=True)
    notes_file = ws / "notes.txt"
    protected_file = ws / "protected.txt"
    notes_file.write_text("HTTP wire test notes\n", encoding="utf-8")
    protected_file.write_text("HTTP wire test protected file\n", encoding="utf-8")

    db_path = tmp_path / "http_demo.db"
    policy_yaml = """
version: 1
policy_id: http-wire-test
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-fs-read
    match: { tool: fs.read, verb: read, resource: "path:**" }
    verdict: allow
  - id: ask-fs-delete
    match: { tool: fs.delete, verb: delete, resource: "path:**" }
    verdict: ask
    reason: "Deletion requires approval"
"""
    policy = load_policy_yaml(policy_yaml)

    # 1. Start Services 1
    store1 = ReceiptStore(db_path)
    b1 = Boundary(policy=policy, receipt_store=store1, session_id="s-http")
    reg1 = ExecutorRegistry()
    reg1.register_fs(ws)
    services1 = AppServices(b1, executor_registry=reg1)

    # Step A: Allowed Read over HTTP POST /v1/crossings
    code, body = _dispatch_handler(
        services1,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "fs.read",
            "verb": "read",
            "resource": f"path:{notes_file.as_posix()}",
            "params": {"path": "notes.txt"},
            "execute": True,
            "session_id": "s-http",
        },
    )
    assert code == 200
    assert body["verdict"] == "allow"
    assert body.get("outcome", {}).get("status") == "success"

    # Step B: Protected Delete over HTTP POST /v1/crossings -> produces ASK
    code, body = _dispatch_handler(
        services1,
        "/v1/crossings",
        method="POST",
        data={
            "tool": "fs.delete",
            "verb": "delete",
            "resource": f"path:{protected_file.as_posix()}",
            "params": {"path": "protected.txt"},
            "execute": True,
            "session_id": "s-http",
        },
    )
    assert code == 200
    assert body["verdict"] == "ask"
    del_cid = body["crossing_id"]
    assert protected_file.exists()

    # Step C: Simulate process termination & restart on same SQLite DB
    del services1
    del b1
    del store1

    store2 = ReceiptStore(db_path)
    b2 = Boundary(policy=policy, receipt_store=store2, session_id="s-http")
    reg2 = ExecutorRegistry()
    reg2.register_fs(ws)
    services2 = AppServices(b2, executor_registry=reg2)

    # Step D: Verify pending approval survived restart via GET /v1/crossings/pending
    code, pending_list = _dispatch_handler(services2, "/v1/crossings/pending", method="GET")
    assert code == 200
    matching = [p for p in pending_list if p["crossing_id"] == del_cid]
    assert len(matching) == 1
    assert protected_file.exists()

    # Step E: Approve crossing via HTTP POST /v1/crossings/{id}/approve
    code, app_res = _dispatch_handler(
        services2,
        f"/v1/crossings/{del_cid}/approve",
        method="POST",
        data={"approved": True, "execute": False},
    )
    assert code == 200
    assert app_res["status"] == "approved"
    assert protected_file.exists()  # Not executed yet

    # Step F: Simulate second process restart (approved-but-not-yet-executed state survival!)
    del services2
    del b2
    del store2

    store3 = ReceiptStore(db_path)
    b3 = Boundary(policy=policy, receipt_store=store3, session_id="s-http")
    reg3 = ExecutorRegistry()
    reg3.register_fs(ws)
    services3 = AppServices(b3, executor_registry=reg3)

    # Step G: Execute approved crossing in restarted process via POST /v1/crossings/{id}/execute
    code, exec_res = _dispatch_handler(
        services3,
        f"/v1/crossings/{del_cid}/execute",
        method="POST",
        data={},
    )
    assert code == 200
    assert exec_res["status"] == "success"
    assert not protected_file.exists()  # File has been deleted!

    # Step H: Duplicate execution rejected fail-closed
    code, dup_res = _dispatch_handler(
        services3,
        f"/v1/crossings/{del_cid}/execute",
        method="POST",
        data={},
    )
    assert code == 400
    assert "not in approved state" in dup_res["error"] or "could not be claimed" in dup_res["error"]

    # Step I: Verify receipt log over HTTP GET /v1/verify
    code, v_res = _dispatch_handler(services3, "/v1/verify", method="GET")
    assert code == 200
    assert v_res["ok"] is True
    assert v_res["total_records"] >= 4
