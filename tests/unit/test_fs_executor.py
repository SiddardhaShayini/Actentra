"""Security and functional tests for the scoped LocalFSExecutor."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from actentra import ActionBlockedError, Boundary
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore, verify_log
from actentra_executors.fs import ExecutorError, LocalFSExecutor, ScopedFSTools


def _workspace_policy(ws: Path, *, constraints_yaml: str = "") -> str:
    ws_posix = ws.resolve().as_posix()
    if constraints_yaml:
        read_rule = f"""
  - id: allow-read
    match: {{ tool: fs.read, verb: read, resource: "path:{ws_posix}/**" }}
    verdict: allow_with_constraints
    constraints:
{constraints_yaml}
  - id: allow-write
    match: {{ tool: fs.write, verb: write, resource: "path:{ws_posix}/**" }}
    verdict: allow_with_constraints
    constraints:
{constraints_yaml}
"""
    else:
        read_rule = f"""
  - id: allow-read
    match: {{ tool: fs.read, verb: read, resource: "path:{ws_posix}/**" }}
    verdict: allow
  - id: allow-write
    match: {{ tool: fs.write, verb: write, resource: "path:{ws_posix}/**" }}
    verdict: allow
"""
    return f"""
version: 1
defaults: {{ verdict: deny }}
rules:
  - id: allow-list
    match: {{ tool: fs.list, verb: read, resource: "path:{ws_posix}/**" }}
    verdict: allow
{read_rule}
  - id: allow-delete
    match: {{ tool: fs.delete, verb: delete, resource: "path:{ws_posix}/**" }}
    verdict: allow
"""


def test_scoped_fs_crud_and_receipts(tmp_path: Path) -> None:
    ws = tmp_path / "work"
    ws.mkdir()
    db_path = tmp_path / "receipts.db"

    policy = load_policy_yaml(_workspace_policy(ws))
    boundary = Boundary(policy=policy, receipt_store=ReceiptStore(db_path), session_id="fs-1")
    tools = ScopedFSTools(boundary, LocalFSExecutor(ws))

    write_res = tools.write_file("sub/hello.txt", "world", create_parents=True)
    assert write_res["written_bytes"] == 5
    assert tools.read_file("sub/hello.txt") == "world"

    entries = tools.list_dir("sub")
    assert entries == [{"name": "hello.txt", "type": "file"}]

    del_res = tools.delete_file("sub/hello.txt")
    assert del_res["deleted"] is True

    vr = verify_log(db_path)
    assert vr.ok is True
    assert vr.total_records == 8


def test_scoped_fs_rejects_traversal_and_trailing_space(tmp_path: Path) -> None:
    ws = tmp_path / "work"
    ws.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("top-secret", encoding="utf-8")

    policy = load_policy_yaml(_workspace_policy(ws))
    boundary = Boundary(policy=policy, receipt_store=ReceiptStore(tmp_path / "r.db"))
    tools = ScopedFSTools(boundary, LocalFSExecutor(ws))

    with pytest.raises(ActionBlockedError):
        tools.read_file("../secret.txt")

    with pytest.raises(ActionBlockedError):
        tools.read_file("note.txt ")

    with pytest.raises(ActionBlockedError):
        tools.read_file(str(outside))


def test_scoped_fs_enforces_constraints(tmp_path: Path) -> None:
    ws = tmp_path / "work"
    ws.mkdir()
    (ws / "big.txt").write_text("0123456789" * 10, encoding="utf-8")
    (ws / "script.ps1").write_text("Write-Host hi", encoding="utf-8")

    constraints = (
        "      max_read_bytes: 20\n"
        "      max_write_bytes: 10\n"
        "      allowed_extensions: [\".txt\", \".md\"]\n"
    )
    policy = load_policy_yaml(_workspace_policy(ws, constraints_yaml=constraints))
    db_path = tmp_path / "r.db"
    boundary = Boundary(policy=policy, receipt_store=ReceiptStore(db_path))
    tools = ScopedFSTools(boundary, LocalFSExecutor(ws))

    with pytest.raises(ExecutorError, match="max_read_bytes"):
        tools.read_file("big.txt")

    with pytest.raises(ExecutorError, match="extension '.ps1' not in"):
        tools.read_file("script.ps1")

    with pytest.raises(ExecutorError, match="max_write_bytes"):
        tools.write_file("small.txt", "0123456789ABCDEF")

    # Failure outcomes must still keep receipt chain valid
    assert verify_log(db_path).ok is True


def test_scoped_fs_blocks_read_only_constraint_and_dir_delete(tmp_path: Path) -> None:
    ws = tmp_path / "work"
    ws.mkdir()
    (ws / "subdir").mkdir()

    constraints = "      read_only: true\n"
    policy = load_policy_yaml(_workspace_policy(ws, constraints_yaml=constraints))
    boundary = Boundary(policy=policy, receipt_store=ReceiptStore(tmp_path / "r.db"))
    tools = ScopedFSTools(boundary, LocalFSExecutor(ws))

    with pytest.raises(ExecutorError, match="read_only"):
        tools.write_file("a.txt", "hi")

    with pytest.raises(ExecutorError, match="Directory deletion"):
        tools.delete_file("subdir")


def test_scoped_fs_blocks_reparse_escape_via_realpath(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = tmp_path / "work"
    ws.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (ws / "link_in").mkdir()

    policy = load_policy_yaml(_workspace_policy(ws))
    boundary = Boundary(policy=policy, receipt_store=ReceiptStore(tmp_path / "r.db"))
    tools = ScopedFSTools(boundary, LocalFSExecutor(ws))

    real_realpath = os.path.realpath

    def fake_realpath(p: str | os.PathLike[str]) -> str:
        s = str(p)
        if "link_in" in s.lower():
            return str(outside_dir / "secret.txt")
        return real_realpath(p)

    monkeypatch.setattr(os.path, "realpath", fake_realpath)

    with pytest.raises(ExecutorError, match="escapes"):
        tools.read_file("link_in/secret.txt")

    with pytest.raises(ExecutorError, match="escapes"):
        tools.write_file("link_in/new.txt", "pwned")


def test_scoped_fs_blocks_windows_junction_escape_if_permitted(tmp_path: Path) -> None:
    import _winapi

    ws = tmp_path / "work"
    ws.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "secret.txt").write_text("junction-secret", encoding="utf-8")

    junction_path = ws / "link_out"
    try:
        _winapi.CreateJunction(str(outside_dir), str(junction_path))
    except OSError:
        pytest.skip("OS or sandbox privilege prevents creating Windows junctions")

    policy = load_policy_yaml(_workspace_policy(ws))
    boundary = Boundary(policy=policy, receipt_store=ReceiptStore(tmp_path / "r.db"))
    tools = ScopedFSTools(boundary, LocalFSExecutor(ws))

    with pytest.raises(ExecutorError, match="escapes"):
        tools.read_file("link_out/secret.txt")


def test_scoped_fs_blocks_symlink_escape_if_supported(tmp_path: Path) -> None:
    ws = tmp_path / "work"
    ws.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link_path = ws / "escape.txt"

    try:
        os.symlink(outside, link_path)
    except OSError:
        pytest.skip("OS privilege prevents creating symlinks in test environment")

    policy = load_policy_yaml(_workspace_policy(ws))
    boundary = Boundary(policy=policy, receipt_store=ReceiptStore(tmp_path / "r.db"))
    tools = ScopedFSTools(boundary, LocalFSExecutor(ws))

    with pytest.raises(ExecutorError, match="escapes allowed base directory|Symlink"):
        tools.read_file("escape.txt")
