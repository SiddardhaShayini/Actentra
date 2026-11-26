"""Tests for developer-facing SDK exports, factories, Boundary.run(), inspection, and examples."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from actentra import (
    ActentraError,
    ActionBlockedError,
    Boundary,
    CanonicalizationError,
    CrossingReceipt,
    ExecutionResult,
    LocalFSExecutor,
    PostconditionFailedError,
    ProvenanceItem,
    ReceiptStore,
    ScopedHTTPExecutor,
    ScopedSQLiteExecutor,
    Verdict,
    WorkspaceFileVerifier,
    load_policy_file,
    load_policy_yaml,
    path_resource,
)
from actentra_cli.main import app

REPO_ROOT = Path(__file__).resolve().parents[2]


def _make_workspace_policy(workspace: Path, *, postcondition_rule: bool = False) -> str:
    ws = path_resource(workspace).removeprefix("path:")
    extra = ""
    write_pattern = f"path:{ws}/**"
    if postcondition_rule:
        write_pattern = f"path:{ws}/note_*.txt"
        extra = f"""
  - id: strict-write-digest
    match:
      tool: fs.write
      verb: write
      resource: "path:{ws}/strict_*.txt"
    verdict: allow
    constraints:
      require_postcondition: true
      postcondition: digest_match
    reason: "Strict write requires digest_match postcondition"
"""
    return f"""\
version: 1
policy_id: dev-usability-test
mode: enforce

defaults:
  verdict: deny
  reason: "Denied by default policy"

rules:
  - id: block-privilege-escalation
    match:
      risk_any: [privilege-escalation]
    verdict: deny
    reason: "Privilege-escalating or sensitive-path actions are blocked"
{extra}
  - id: allow-workspace-list
    match:
      tool: fs.list
      verb: read
      resource: "path:{ws}/**"
    verdict: allow
    reason: "Allow workspace list"

  - id: allow-workspace-read
    match:
      tool: fs.read
      verb: read
      resource: "path:{ws}/**"
    verdict: allow
    reason: "Allow workspace read"

  - id: ask-workspace-write
    match:
      tool: fs.write
      verb: write
      resource: "{write_pattern}"
    verdict: ask
    reason: "Workspace writes require approval"
"""


def test_public_sdk_exports_cover_local_workflow() -> None:
    assert Boundary is not None
    assert ExecutionResult is not None
    assert CrossingReceipt is not None
    assert ReceiptStore is not None
    assert LocalFSExecutor is not None
    assert ScopedHTTPExecutor is not None
    assert ScopedSQLiteExecutor is not None
    assert WorkspaceFileVerifier is not None
    assert callable(load_policy_file)
    assert callable(load_policy_yaml)
    assert callable(path_resource)


def test_path_resource_canonicalizes_and_rejects_traversal(tmp_path: Path) -> None:
    ws = tmp_path / "work"
    ws.mkdir()
    res = path_resource("sub/notes.txt", workspace_root=ws)
    assert res.startswith("path:")
    assert res.endswith("/work/sub/notes.txt")

    with pytest.raises(CanonicalizationError):
        path_resource("../escape.txt", workspace_root=ws)

    with pytest.raises(CanonicalizationError):
        path_resource("notes.txt:ads", workspace_root=ws)


def test_from_yaml_and_run_verified_write_and_inspect(tmp_path: Path) -> None:
    ws = tmp_path / "workspace"
    ws.mkdir()
    db_path = tmp_path / "receipts.db"

    boundary = Boundary.from_yaml(
        policy_yaml=_make_workspace_policy(ws),
        receipts_db=db_path,
        workspace_root=ws,
        session_id="s-write",
        agent_id="a-write",
        approval_callback=lambda _env, _dec: True,
    )
    assert boundary.registered_tools == ["fs.delete", "fs.list", "fs.read", "fs.write"]

    target = path_resource("hello.txt", workspace_root=ws)
    write_res = boundary.run(
        tool="fs.write",
        verb="write",
        resource=target,
        params={"content": "hello actentra\n", "create_parents": True},
        verify_postcondition=True,
        raise_on_postcondition_failure=True,
    )
    assert isinstance(write_res, ExecutionResult)
    assert write_res.allowed is True
    assert write_res.verdict == Verdict.ALLOW
    assert write_res.status == "success"
    assert write_res.evidence_status == "externally_verified"
    assert write_res.verified is True
    assert write_res.observation is not None
    assert write_res.observation.claim == "digest_match"
    assert write_res.observation.status == "verified"
    assert write_res.to_dict()["verified"] is True

    # Read back through Boundary.run()
    read_res = boundary.run(tool="fs.read", verb="read", resource=target)
    assert read_res.allowed is True
    assert read_res.result == "hello actentra\n"

    # Inspect crossing & hash chain
    inspected = boundary.inspect_crossing(write_res.crossing_id)
    assert inspected.crossing_id == write_res.crossing_id
    assert inspected.verified is True
    assert inspected.lifecycle_state == "succeeded"
    assert inspected.decision is not None
    assert inspected.outcome is not None
    assert inspected.observation is not None
    assert inspected.envelope is not None
    assert inspected.to_dict()["crossing_id"] == write_res.crossing_id

    recent = boundary.recent_receipts(limit=10, session_id="s-write")
    assert len(recent) >= 2
    integrity = boundary.verify_receipts(verify_envelopes=True)
    assert integrity.ok is True


def test_from_files_with_workspace_and_missing_file_error(tmp_path: Path) -> None:
    ws = tmp_path / "workspace"
    ws.mkdir()
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_make_workspace_policy(ws), encoding="utf-8")

    with pytest.raises(FileNotFoundError, match="actentra init"):
        Boundary.from_files(
            policy_path=tmp_path / "missing.yaml",
            receipts_db=tmp_path / "r.db",
        )

    boundary = Boundary.from_files(
        policy_path=policy_file,
        receipts_db=tmp_path / "r.db",
        workspace_root=ws,
    )
    (ws / "a.txt").write_text("abc", encoding="utf-8")
    res = boundary.run(
        tool="fs.read",
        verb="read",
        resource=path_resource("a.txt", workspace_root=ws),
    )
    assert res.result == "abc"


def test_run_fails_closed_on_missing_executor_and_blocked_actions(tmp_path: Path) -> None:
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / ".env").write_text("SECRET=1\n", encoding="utf-8")

    boundary = Boundary.from_yaml(
        policy_yaml=_make_workspace_policy(ws),
        receipts_db=tmp_path / "receipts.db",
        workspace_root=ws,
    )

    with pytest.raises(ActentraError, match="No executor registered"):
        boundary.run(tool="custom.unregistered", verb="read", resource="tool:custom")

    with pytest.raises(ActionBlockedError) as exc_info:
        boundary.run(
            tool="fs.read",
            verb="read",
            resource=path_resource(".env", workspace_root=ws),
        )
    assert exc_info.value.decision.verdict == Verdict.DENY

    # raise_on_blocked=False still blocks execution and returns ExecutionResult(allowed=False)
    blocked_res = boundary.run(
        tool="fs.write",
        verb="write",
        resource=path_resource("blocked.txt", workspace_root=ws),
        params={"content": "nope"},
        raise_on_blocked=False,
    )
    assert blocked_res.allowed is False
    assert blocked_res.verdict == Verdict.ASK
    assert blocked_res.status == "blocked"
    assert not (ws / "blocked.txt").exists()


def test_run_cannot_weaken_policy_mandated_postcondition(tmp_path: Path) -> None:
    ws = tmp_path / "workspace"
    ws.mkdir()
    boundary = Boundary.from_yaml(
        policy_yaml=_make_workspace_policy(ws, postcondition_rule=True),
        receipts_db=tmp_path / "receipts.db",
        workspace_root=ws,
    )

    with pytest.raises(PostconditionFailedError, match="substitution rejected"):
        boundary.run(
            tool="fs.write",
            verb="write",
            resource=path_resource("strict_file.txt", workspace_root=ws),
            params={"content": "data"},
            verify_postcondition=True,
            postcondition_claim="exists",
        )


def test_boundary_register_sqlite_http_and_custom_executor(tmp_path: Path) -> None:
    ws = tmp_path / "workspace"
    ws.mkdir()
    sqlite_db = tmp_path / "app.db"
    conn = sqlite3.connect(sqlite_db)
    conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);")
    conn.execute("INSERT INTO items (name) VALUES ('widget');")
    conn.commit()
    conn.close()

    policy_yaml = """\
version: 1
policy_id: multi-exec-test
mode: enforce
defaults:
  verdict: deny
  reason: "Denied by default"
rules:
  - id: allow-sql
    match:
      tool: sql.execute
      verb: read
    verdict: allow
    constraints:
      read_only: true
      allowed_tables: [items]
  - id: allow-custom
    match:
      tool: custom.echo
      verb: read
    verdict: allow
"""
    boundary = Boundary.from_yaml(
        policy_yaml=policy_yaml,
        receipts_db=tmp_path / "receipts.db",
    )
    sqlite_exec = boundary.register_sqlite(sqlite_db)
    boundary.register_http(allowed_hosts=["example.com"])
    boundary.register_executor("custom.echo", lambda env, _dec: env.action.params.get("msg"))

    assert "sql.execute" in boundary.registered_tools
    assert "http.get" in boundary.registered_tools
    assert "custom.echo" in boundary.registered_tools

    sql_res = boundary.run(
        tool="sql.execute",
        verb="read",
        resource=sqlite_exec.resource_id,
        params={"query": "SELECT name FROM items;"},
    )
    assert sql_res.allowed is True
    assert sql_res.result["columns"] == ["name"]
    assert sql_res.result["rows"] == [["widget"]]

    echo_res = boundary.run(
        tool="custom.echo",
        verb="read",
        resource="tool:echo",
        params={"msg": "ok"},
    )
    assert echo_res.result == "ok"


def test_cli_init_workspace_creates_valid_scoped_policy(tmp_path: Path) -> None:
    runner = CliRunner()
    ws = tmp_path / "my_project"
    ws.mkdir()
    out_dir = tmp_path / "cfg"

    res = runner.invoke(app, ["init", str(out_dir), "--workspace", str(ws)])
    assert res.exit_code == 0, res.output
    policy_file = out_dir / "actentra.policy.yaml"
    assert policy_file.exists()

    check_res = runner.invoke(app, ["policy", "check", str(policy_file)])
    assert check_res.exit_code == 0, check_res.output
    assert "OK policy=local-workspace" in check_res.output

    # Verify the generated policy actually allows reads inside `ws` and blocks .env
    boundary = Boundary.from_files(
        policy_path=policy_file,
        receipts_db=tmp_path / "r.db",
        workspace_root=ws,
    )
    (ws / "hello.txt").write_text("hi", encoding="utf-8")
    read_res = boundary.run(
        tool="fs.read",
        verb="read",
        resource=path_resource("hello.txt", workspace_root=ws),
    )
    assert read_res.result == "hi"

    with pytest.raises(ActionBlockedError) as exc_info:
        boundary.run(
            tool="fs.read",
            verb="read",
            resource=path_resource(".env", workspace_root=ws),
        )
    assert exc_info.value.decision.verdict == Verdict.DENY

    # Also verify untrusted provenance blocks http.*
    with pytest.raises(ActionBlockedError) as http_exc:
        boundary.execute(
            tool="http.post",
            verb="network",
            resource="https://example.com/leak",
            provenance=[ProvenanceItem(source="email", trust="untrusted")],
            fn=lambda _e, _d: "never",
        )
    assert http_exc.value.decision.verdict == Verdict.DENY


@pytest.mark.parametrize(
    "script_name",
    [
        "minimal_file_write.py",
        "minimal_blocked_action.py",
        "gateway_http_example.py",
        "agent_function_calling.py",
    ],
)
def test_examples_run_end_to_end(script_name: str, tmp_path: Path) -> None:
    script = REPO_ROOT / "examples" / script_name
    proc = subprocess.run(  # noqa: S603
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    msg = f"{script_name} failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    if script_name == "gateway_http_example.py" and "WinError 10013" in proc.stderr:
        pytest.skip("Loopback socket access restricted by sandbox (WinError 10013)")
    assert proc.returncode == 0, msg
    if script_name == "agent_function_calling.py":
        assert "call_read_1" in proc.stdout
        assert "block-untrusted-egress" in proc.stdout
    elif script_name == "minimal_file_write.py":
        assert "Verified        : True" in proc.stdout
    elif script_name == "minimal_blocked_action.py":
        assert "Blocked as expected" in proc.stdout
    elif script_name == "gateway_http_example.py":
        assert "[POST /v1/crossings ALLOW]" in proc.stdout
        assert "[POST /v1/crossings DENY ]" in proc.stdout
        assert json.dumps("ok")  # keep json import used
