"""Tests for Phase 4 Cross-Agent Task Handoffs and Continuity."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from actentra.boundary import Boundary
from actentra_cli.main import app
from actentra_core.canonicalize import canonicalize_windows_path
from actentra_core.handoffs import (
    TaskHandoffRecord,
    UnauthorizedAgentHandoffError,
    build_handoff,
)
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_gateway.demo import run_handoff_demonstration
from actentra_gateway.http_service import ActentraHTTPHandler
from actentra_gateway.services import AppServices, ExecutorRegistry

runner = CliRunner()

_STARTER_POLICY = """\
version: 1
policy_id: test-handoff-policy
mode: enforce
defaults:
  verdict: deny
rules:
  - id: allow-fs-reads
    match:
      tool: "fs.read"
      verb: read
    verdict: allow
  - id: allow-fs-writes
    match:
      tool: "fs.write"
      verb: write
    verdict: allow
"""


def _dispatch_handler(
    services: AppServices,
    path: str,
    method: str = "GET",
    data: Any = None,
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

    body_bytes = json.dumps(data).encode("utf-8") if data is not None else b""
    handler.headers = {  # type: ignore[assignment]
        "Content-Length": str(len(body_bytes)),
        "Content-Type": "application/json",
        "Origin": "http://127.0.0.1:8080",
    }
    handler.rfile = io.BytesIO(body_bytes)

    if method == "GET":
        handler.do_GET()
    elif method == "POST":
        handler.do_POST()
    elif method == "DELETE":
        handler.do_DELETE()
    else:
        raise ValueError(f"Unsupported method {method}")

    raw_output = handler.wfile.getvalue().decode("utf-8")
    status_code = int(raw_output.splitlines()[0].split()[1])
    parts = raw_output.split("\r\n\r\n", 1)
    body_str = parts[1] if len(parts) > 1 else ""
    try:
        parsed_body = json.loads(body_str)
    except Exception:
        parsed_body = body_str
    return status_code, parsed_body


def test_handoff_schema_validation() -> None:
    """Verify TaskHandoffRecord conforms strictly to spec/handoff.v1.schema.json."""
    import jsonschema  # type: ignore[import-untyped]

    schema_path = Path("spec/handoff.v1.schema.json")
    assert schema_path.exists()
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    hnd = build_handoff(
        task_id="task_pipeline_001",
        initiator_agent_id="agent_planner",
        assigned_agent_id="agent_builder",
        verifier_agent_id="agent_auditor",
        allowed_verbs=["read", "write"],
        allowed_resources=["path:c:/workspace/*"],
        prior_crossings=["cr_001"],
        prior_observations=["obs_001"],
        assertions={"path:c:/workspace/data.json": {"claim": "exists"}},
        contradictions=["prior drift note"],
    )
    jsonschema.validate(instance=hnd.to_dict(), schema=schema)


def test_handoff_record_integrity_and_hashing() -> None:
    """TaskHandoffRecord cryptographically binds its payload to detect tampering."""
    hnd = build_handoff(
        task_id="task_release_001",
        initiator_agent_id="agent_planner",
        assigned_agent_id="agent_builder",
        verifier_agent_id="agent_auditor",
        allowed_verbs=["write"],
        assertions={"path:c:/workspace/artifact.bin": "exists"},
    )
    assert hnd.verify_integrity() is True

    # Tampered copy
    tampered = TaskHandoffRecord(
        handoff_id=hnd.handoff_id,
        handoff_version=hnd.handoff_version,
        task_id=hnd.task_id,
        status="active",
        current_step=hnd.current_step,
        initiator_agent_id=hnd.initiator_agent_id,
        assigned_agent_id="agent_attacker",  # modified
        verifier_agent_id=hnd.verifier_agent_id,
        allowed_verbs=hnd.allowed_verbs,
        allowed_resources=hnd.allowed_resources,
        prior_crossings=hnd.prior_crossings,
        prior_observations=hnd.prior_observations,
        assertions=hnd.assertions,
        contradictions=hnd.contradictions,
        created_at=hnd.created_at,
        expires_at=hnd.expires_at,
        handoff_hash=hnd.handoff_hash,
    )
    assert tampered.verify_integrity() is False


def test_handoff_authority_and_freshness() -> None:
    """TaskHandoffRecord enforces assigned caller identity and freshness bounds."""
    hnd = build_handoff(
        task_id="task_test_001",
        initiator_agent_id="agent_planner",
        assigned_agent_id="agent_builder",
        verifier_agent_id="agent_auditor",
        ttl_seconds=60.0,
    )
    # Authorized caller succeeds
    hnd.validate_caller("agent_builder")

    # Unauthorized caller fails closed
    with pytest.raises(UnauthorizedAgentHandoffError):
        hnd.validate_caller("agent_rogue")

    # Expired handoff fails closed
    # 2026-11-17T15:00:00.000Z in future timestamp check
    assert hnd.is_fresh(now=2500000000.0) is False


def test_receipt_store_handoff_persistence(tmp_path: Path) -> None:
    """ReceiptStore correctly commits and queries task handoff records in SQLite."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)

    hnd = build_handoff(
        task_id="task_deploy_001",
        initiator_agent_id="agent_planner",
        assigned_agent_id="agent_builder",
        verifier_agent_id="agent_auditor",
        prior_crossings=["cr_1"],
    )
    store.record_handoff(hnd)
    assert store.count_handoffs() == 1
    assert store.count_handoffs(task_id="task_deploy_001") == 1

    fetched = store.get_handoff(hnd.handoff_id)
    assert fetched is not None
    assert fetched.task_id == "task_deploy_001"
    assert fetched.assigned_agent_id == "agent_builder"

    active = store.get_active_handoff_by_task("task_deploy_001")
    assert active is not None
    assert active.handoff_id == hnd.handoff_id

    # Update status
    store.update_handoff_status(hnd.handoff_id, "completed")
    updated = store.get_handoff(hnd.handoff_id)
    assert updated is not None
    assert updated.status == "completed"

    # Process restart simulation: reopen same DB
    store2 = ReceiptStore(db_file)
    reloaded = store2.get_handoff(hnd.handoff_id)
    assert reloaded is not None
    assert reloaded.status == "completed"


def test_independent_verification_and_drift_detection(tmp_path: Path) -> None:
    """Agent C verifier detects state matches and catches out-of-band drift."""
    ws = tmp_path / "ws"
    ws.mkdir()
    target_file = ws / "manifest.json"
    manifest_content = '{"release": "1.0.0"}\n'
    target_file.write_text(manifest_content, encoding="utf-8", newline="\n")
    canon_res = f"path:{canonicalize_windows_path(str(target_file))}"

    digest = f"sha256:{hashlib.sha256(manifest_content.encode('utf-8')).hexdigest()}"

    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_STARTER_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    reg = ExecutorRegistry()
    reg.register_fs(ws)
    services = AppServices(boundary, executor_registry=reg)

    # Create handoff with assertion
    hnd = services.create_task_handoff(
        task_id="task_release_002",
        initiator_agent_id="agent_planner",
        assigned_agent_id="agent_builder",
        verifier_agent_id="agent_auditor",
        assertions={canon_res: {"claim": "exists", "digest": digest}},
    )
    hnd_id = hnd["handoff_id"]

    # 1. Independent verification succeeds
    res_success = services.verify_task_handoff(hnd_id, verifier_agent_id="agent_auditor")
    assert res_success["verified"] is True
    assert res_success["status"] == "completed"
    assert len(res_success["contradictions"]) == 0

    # 2. Simulate out-of-band content drift / corruption
    target_file.write_text('{"release": "1.0.0-corrupted"}\n', encoding="utf-8", newline="\n")

    # Create new handoff expecting original digest
    hnd_drift = services.create_task_handoff(
        task_id="task_release_002",
        initiator_agent_id="agent_builder",
        assigned_agent_id="agent_auditor",
        verifier_agent_id="agent_auditor",
        assertions={canon_res: {"claim": "exists", "digest": digest}},
    )
    res_drift = services.verify_task_handoff(
        hnd_drift["handoff_id"], verifier_agent_id="agent_auditor"
    )
    assert res_drift["verified"] is False
    assert res_drift["status"] == "contradicted"
    assert len(res_drift["contradictions"]) > 0


def test_handoff_http_endpoints(tmp_path: Path) -> None:
    """REST APIs expose handoff creation, advancement, and independent verification."""
    ws = tmp_path / "ws"
    ws.mkdir()
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_STARTER_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    reg = ExecutorRegistry()
    reg.register_fs(ws)
    services = AppServices(boundary, executor_registry=reg)

    # 1. POST /v1/handoffs (create)
    code, created = _dispatch_handler(
        services,
        "/v1/handoffs",
        method="POST",
        data={
            "task_id": "task_http_001",
            "initiator_agent_id": "agent_planner",
            "assigned_agent_id": "agent_builder",
            "verifier_agent_id": "agent_auditor",
            "allowed_verbs": ["read", "write"],
        },
    )
    assert code == 201
    hnd_id = created["handoff_id"]
    assert created["task_id"] == "task_http_001"

    # 2. GET /v1/handoffs/{id}
    code, fetched = _dispatch_handler(services, f"/v1/handoffs/{hnd_id}")
    assert code == 200
    assert fetched["handoff_id"] == hnd_id

    # 3. POST /v1/handoffs/{id}/advance with unauthorized agent -> 403 Forbidden
    code, err_adv = _dispatch_handler(
        services,
        f"/v1/handoffs/{hnd_id}/advance",
        method="POST",
        data={
            "caller_agent_id": "agent_intruder",
            "next_agent_id": "agent_auditor",
        },
    )
    assert code == 403
    assert err_adv.get("code") == "unauthorized_agent"

    # 4. POST /v1/handoffs/{id}/advance with authorized agent -> 200 OK
    code, advanced = _dispatch_handler(
        services,
        f"/v1/handoffs/{hnd_id}/advance",
        method="POST",
        data={
            "caller_agent_id": "agent_builder",
            "next_agent_id": "agent_auditor",
        },
    )
    assert code == 200
    assert advanced["current_step"] == 2
    assert advanced["assigned_agent_id"] == "agent_auditor"

    # 5. POST /v1/bundle/export includes task_handoffs
    bundle = services.export_audit_bundle()
    assert "task_handoffs" in bundle
    assert len(bundle["task_handoffs"]) >= 2


def test_handoff_cli_commands(tmp_path: Path) -> None:
    """CLI commands for task handoffs operate correctly."""
    db_file = tmp_path / "cli_receipts.db"

    # 1. Create handoff via CLI
    res_create = runner.invoke(
        app,
        [
            "handoff",
            "create",
            "task_cli_001",
            "agent_planner",
            "agent_builder",
            "agent_auditor",
            "--verbs",
            "read,write",
            "--db",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    assert "Created Task Handoff hnd_" in res_create.stdout

    # 2. List handoffs via CLI
    res_list = runner.invoke(app, ["handoff", "list", "--db", str(db_file)])
    assert res_list.exit_code == 0
    assert "task_cli_001" in res_list.stdout
    hnd_id = res_list.stdout.split("id=")[1].split()[0]

    # 3. Show handoff via CLI
    res_show = runner.invoke(app, ["handoff", "show", hnd_id, "--db", str(db_file)])
    assert res_show.exit_code == 0
    assert "task_cli_001" in res_show.stdout

    # 4. Advance handoff via CLI with unauthorized caller -> fails code 1
    res_adv_unauth = runner.invoke(
        app,
        [
            "handoff",
            "advance",
            hnd_id,
            "agent_wrong",
            "agent_auditor",
            "--db",
            str(db_file),
        ],
    )
    assert res_adv_unauth.exit_code == 1
    assert "Unauthorized" in res_adv_unauth.stdout or "Unauthorized" in res_adv_unauth.stderr

    # 5. Advance handoff via CLI with authorized caller
    res_adv = runner.invoke(
        app,
        [
            "handoff",
            "advance",
            hnd_id,
            "agent_builder",
            "agent_auditor",
            "--db",
            str(db_file),
        ],
    )
    assert res_adv.exit_code == 0
    assert "Advanced handoff to Step 2" in res_adv.stdout


def test_run_handoff_demonstration_end_to_end() -> None:
    """Execute full 7-step cross-agent handoff demonstration runner."""
    result = run_handoff_demonstration(verbose=False)
    assert result.ok is True
    assert result.unauthorized_blocked is True
    assert result.independent_verified is True
    assert result.drift_detected is True
    assert result.steps_executed >= 7
    assert result.causal_trace["dag_verified"] is True
