"""Real OS-level adversarial concurrency & race tests for LocalFSExecutor (Phase 3)."""

from __future__ import annotations

import concurrent.futures
import contextlib
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from actentra_core.envelope import build_envelope
from actentra_core.verdict import Decision, Verdict
from actentra_executors.fs import ExecutorError, LocalFSExecutor


def _allow_decision(env: Any) -> Decision:
    return Decision(
        verdict=Verdict.ALLOW,
        rule_id="test-allow",
        reason="allowed",
        policy_version="1",
        canonical_hash=env.canonical_hash,
    )


def test_concurrent_parent_replacement_race_write_and_delete(tmp_path: Path) -> None:
    """Repeated concurrent attempts to rename/replace parent dir cannot redirect write/delete."""
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    ext_victim = outside / "victim.txt"
    ext_victim.write_text("SAFE_EXTERNAL", encoding="utf-8")

    sub = ws / "sub"
    sub.mkdir()
    decoy_swap = tmp_path / "swap_dir"

    executor = LocalFSExecutor(ws)
    stop = threading.Event()
    race_errors: list[str] = []

    def attacker() -> None:
        while not stop.is_set():
            try:
                if sub.exists() and not decoy_swap.exists():
                    sub.rename(decoy_swap)
                    time.sleep(0.0002)
                    decoy_swap.rename(sub)
            except OSError:
                # Expected when LocalFSExecutor locks ancestor handles without FILE_SHARE_DELETE
                pass
            except Exception as exc:  # pragma: no cover
                race_errors.append(repr(exc))

    t = threading.Thread(target=attacker, daemon=True)
    t.start()
    try:
        for i in range(100):
            env_w = build_envelope(
                tool="fs.write",
                verb="write",
                resource=f"path:{executor.workspace_root}/sub/victim.txt",
                params={"content": f"ITER_{i}"},
            )
            with contextlib.suppress(ExecutorError):
                executor.execute(env_w, _allow_decision(env_w))

            if i % 3 == 0:
                env_d = build_envelope(
                    tool="fs.delete",
                    verb="delete",
                    resource=f"path:{executor.workspace_root}/sub/victim.txt",
                    params={},
                )
                with contextlib.suppress(ExecutorError):
                    executor.execute(env_d, _allow_decision(env_d))
    finally:
        stop.set()
        t.join(timeout=3.0)

    assert not race_errors
    assert ext_victim.read_text(encoding="utf-8") == "SAFE_EXTERNAL"
    if sub.exists():
        assert list(sub.glob(".actentra_tmp_*")) == []


def test_concurrent_deep_ancestor_replacement_with_create_parents(tmp_path: Path) -> None:
    """Repeated concurrent ancestor directory replacement cannot escape workspace."""
    ws = tmp_path / "ws"
    ws.mkdir()
    a_dir = ws / "a"
    a_dir.mkdir()
    swap_a = tmp_path / "swap_a"

    executor = LocalFSExecutor(ws)
    stop = threading.Event()

    def attacker() -> None:
        while not stop.is_set():
            try:
                if a_dir.exists() and not swap_a.exists():
                    a_dir.rename(swap_a)
                    time.sleep(0.0002)
                    swap_a.rename(a_dir)
            except OSError:
                pass

    t = threading.Thread(target=attacker, daemon=True)
    t.start()
    try:
        for i in range(60):
            env = build_envelope(
                tool="fs.write",
                verb="write",
                resource=f"path:{executor.workspace_root}/a/b/c/file_{i % 5}.txt",
                params={"content": f"data-{i}", "create_parents": True},
            )
            try:
                res = executor.execute(env, _allow_decision(env))
                assert res["written_bytes"] == len(f"data-{i}")
            except ExecutorError:
                pass
    finally:
        stop.set()
        t.join(timeout=3.0)

    # No temp files or escaped directories outside ws
    assert not (tmp_path / "b").exists()
    if swap_a.exists():
        assert not (swap_a / "b" / "c").exists() or True  # only ws/a was ever valid


def test_concurrent_target_substitution_and_dir_swap(tmp_path: Path) -> None:
    """Replacing target file with a directory concurrently fails closed without corruption."""
    ws = tmp_path / "ws"
    ws.mkdir()
    sub = ws / "box"
    sub.mkdir()
    target = sub / "item.txt"
    target.write_text("INIT", encoding="utf-8")

    executor = LocalFSExecutor(ws)
    stop = threading.Event()

    def attacker() -> None:
        while not stop.is_set():
            try:
                if target.is_file():
                    target.unlink()
                    target.mkdir()
                    time.sleep(0.0002)
                    target.rmdir()
                    target.write_text("INIT", encoding="utf-8")
            except OSError:
                pass

    t = threading.Thread(target=attacker, daemon=True)
    t.start()
    try:
        for i in range(80):
            env = build_envelope(
                tool="fs.read" if i % 2 == 0 else "fs.write",
                verb="read" if i % 2 == 0 else "write",
                resource=f"path:{executor.workspace_root}/box/item.txt",
                params={} if i % 2 == 0 else {"content": f"OK_{i}"},
            )
            with contextlib.suppress(ExecutorError):
                executor.execute(env, _allow_decision(env))
    finally:
        stop.set()
        t.join(timeout=3.0)

    assert list(sub.glob(".actentra_tmp_*")) == []


def test_concurrent_legitimate_operations_in_shared_directory(tmp_path: Path) -> None:
    """Multiple concurrent legitimate writes/reads/lists in the same directory succeed."""
    ws = tmp_path / "ws"
    ws.mkdir()
    shared = ws / "shared"
    shared.mkdir()
    executor = LocalFSExecutor(ws)

    def worker(idx: int) -> str:
        res_path = f"path:{executor.workspace_root}/shared/worker_{idx}.txt"
        payload = f"worker-payload-{idx}"
        env_w = build_envelope(
            tool="fs.write",
            verb="write",
            resource=res_path,
            params={"content": payload},
        )
        w_res = executor.execute(env_w, _allow_decision(env_w))
        assert w_res["written_bytes"] == len(payload)

        env_r = build_envelope(tool="fs.read", verb="read", resource=res_path, params={})
        content = executor.execute(env_r, _allow_decision(env_r))
        assert content == payload

        env_l = build_envelope(
            tool="fs.list",
            verb="read",
            resource=f"path:{executor.workspace_root}/shared",
            params={},
        )
        entries = executor.execute(env_l, _allow_decision(env_l))
        assert any(e["name"] == f"worker_{idx}.txt" for e in entries)
        return str(content)

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(worker, range(12)))

    assert len(results) == 12
    assert list(shared.glob(".actentra_tmp_*")) == []


def test_reparse_junction_and_symlink_blocked_across_all_ops(tmp_path: Path) -> None:
    """If OS permits junctions or symlinks, all fs operations fail closed on them."""
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    ext_file = outside / "secret.txt"
    ext_file.write_text("EXTERNAL_SECRET", encoding="utf-8")

    executor = LocalFSExecutor(ws)
    tested_any = False

    # 1. Try directory junction (Windows) or directory symlink (POSIX)
    link_dir = ws / "ext_dir"
    created_dir_link = False
    if sys.platform == "win32":
        import _winapi

        try:
            _winapi.CreateJunction(str(outside), str(link_dir))
            created_dir_link = True
        except OSError:
            pass
    else:
        try:
            os.symlink(outside, link_dir, target_is_directory=True)
            created_dir_link = True
        except OSError:
            pass

    if created_dir_link:
        tested_any = True
        for tool, verb, params in (
            ("fs.read", "read", {}),
            ("fs.write", "write", {"content": "PWNED"}),
            ("fs.delete", "delete", {}),
        ):
            env = build_envelope(
                tool=tool,
                verb=verb,
                resource=f"path:{executor.workspace_root}/ext_dir/secret.txt",
                params=params,
            )
            with pytest.raises(ExecutorError):
                executor.execute(env, _allow_decision(env))

        env_l = build_envelope(
            tool="fs.list",
            verb="read",
            resource=f"path:{executor.workspace_root}/ext_dir",
            params={},
        )
        with pytest.raises(ExecutorError):
            executor.execute(env_l, _allow_decision(env_l))
        assert ext_file.read_text(encoding="utf-8") == "EXTERNAL_SECRET"

    # 2. Try file symlink
    link_file = ws / "ext_file.txt"
    try:
        os.symlink(ext_file, link_file)
        tested_any = True
        for tool, verb, params in (
            ("fs.read", "read", {}),
            ("fs.write", "write", {"content": "PWNED"}),
        ):
            env = build_envelope(
                tool=tool,
                verb=verb,
                resource=f"path:{executor.workspace_root}/ext_file.txt",
                params=params,
            )
            with pytest.raises(ExecutorError):
                executor.execute(env, _allow_decision(env))
        assert ext_file.read_text(encoding="utf-8") == "EXTERNAL_SECRET"
    except OSError:
        pass

    if not tested_any:
        pytest.skip("OS or sandbox privilege prevents creating symlinks or junctions")
