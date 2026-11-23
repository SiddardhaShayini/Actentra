"""Comprehensive security and regression tests for Phase 4 executor hardening.

Covers:
- ACT-05: SQLite executor table-level authorizer, CTE/subquery/JOIN/view/trigger defense,
  ATTACH/DETACH/PRAGMA/schema modification blocking.
- ACT-08: Filesystem executor atomic writes, post-open descriptor verification,
  symlink/junction/reparse-point escape blocking, ancestor traversal defense.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from actentra_core.envelope import build_envelope
from actentra_core.verdict import Decision, Verdict
from actentra_executors.fs import ExecutorError, LocalFSExecutor
from actentra_executors.sqlite import ScopedSQLiteExecutor

# ==============================================================================
# Helpers & Fixtures
# ==============================================================================


def _setup_security_test_db(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, item TEXT, amount REAL);")
        conn.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY, secret_key TEXT);")
        conn.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY, action TEXT);")

        conn.execute("INSERT INTO orders VALUES (1, 'book', 19.99);")
        conn.execute("INSERT INTO orders VALUES (2, 'pen', 2.50);")
        conn.execute("INSERT INTO secrets VALUES (1, 'MASTER_KEY_SECRET');")
        conn.execute("INSERT INTO audit_log VALUES (1, 'initial_entry');")

        # View referencing only orders (safe)
        conn.execute("CREATE VIEW v_safe_orders AS SELECT id, item FROM orders;")
        # View referencing secrets (unsafe for unauthorized callers)
        conn.execute(
            "CREATE VIEW v_leaky_secrets AS SELECT orders.id, secrets.secret_key "
            "FROM orders JOIN secrets ON orders.id = secrets.id;"
        )
        # Trigger that accesses secrets upon orders insertion
        conn.execute(
            "CREATE TRIGGER trg_orders_insert AFTER INSERT ON orders "
            "BEGIN INSERT INTO secrets VALUES (new.id + 100, 'auto_generated'); END;"
        )
        conn.commit()
    finally:
        conn.close()


# ==============================================================================
# SQLite Executor Security Tests (ACT-05)
# ==============================================================================


class TestSQLiteTableLevelAuthorization:
    """Tests for ACT-05 table isolation and authorizer enforcement."""

    def test_authorized_table_direct_query_succeeds(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        _setup_security_test_db(db)
        executor = ScopedSQLiteExecutor(db)

        env = build_envelope(
            tool="sql.execute",
            verb="read",
            resource=f"{executor.resource_id}#orders",
            params={"query": "SELECT id, item FROM orders WHERE id = ?", "args": [1]},
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )
        result = executor.execute(env, dec)
        assert result["row_count"] == 1
        assert result["rows"] == [[1, "book"]]

    def test_unauthorized_table_direct_query_blocked(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        _setup_security_test_db(db)
        executor = ScopedSQLiteExecutor(db)

        # Policy authorizes 'orders', but query attempts to read 'secrets'
        env = build_envelope(
            tool="sql.execute",
            verb="read",
            resource=f"{executor.resource_id}#orders",
            params={"query": "SELECT * FROM secrets", "args": []},
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )
        with pytest.raises(ExecutorError, match="Unauthorized table or SQL operation"):
            executor.execute(env, dec)

    def test_join_based_bypass_blocked(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        _setup_security_test_db(db)
        executor = ScopedSQLiteExecutor(db)

        env = build_envelope(
            tool="sql.execute",
            verb="read",
            resource=f"{executor.resource_id}#orders",
            params={
                "query": "SELECT orders.id, secrets.secret_key FROM orders "
                "JOIN secrets ON orders.id = secrets.id",
                "args": [],
            },
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )
        with pytest.raises(ExecutorError, match="Unauthorized table or SQL operation"):
            executor.execute(env, dec)

    def test_cte_with_clause_bypass_blocked(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        _setup_security_test_db(db)
        executor = ScopedSQLiteExecutor(db)

        env = build_envelope(
            tool="sql.execute",
            verb="read",
            resource=f"{executor.resource_id}#orders",
            params={
                "query": "WITH leaked AS (SELECT * FROM secrets) SELECT * FROM leaked",
                "args": [],
            },
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )
        with pytest.raises(ExecutorError, match="Unauthorized table or SQL operation"):
            executor.execute(env, dec)

    def test_subquery_in_clause_bypass_blocked(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        _setup_security_test_db(db)
        executor = ScopedSQLiteExecutor(db)

        env = build_envelope(
            tool="sql.execute",
            verb="read",
            resource=f"{executor.resource_id}#orders",
            params={
                "query": "SELECT * FROM orders WHERE id IN (SELECT id FROM secrets)",
                "args": [],
            },
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )
        with pytest.raises(ExecutorError, match="Unauthorized table or SQL operation"):
            executor.execute(env, dec)

    def test_scalar_subquery_bypass_blocked(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        _setup_security_test_db(db)
        executor = ScopedSQLiteExecutor(db)

        env = build_envelope(
            tool="sql.execute",
            verb="read",
            resource=f"{executor.resource_id}#orders",
            params={
                "query": "SELECT (SELECT secret_key FROM secrets LIMIT 1)",
                "args": [],
            },
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )
        with pytest.raises(ExecutorError, match="Unauthorized table or SQL operation"):
            executor.execute(env, dec)

    def test_view_accessing_unauthorized_underlying_table_blocked(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        _setup_security_test_db(db)
        executor = ScopedSQLiteExecutor(db)

        # Calling view that queries secrets when only orders is authorized
        env = build_envelope(
            tool="sql.execute",
            verb="read",
            resource=f"{executor.resource_id}#orders",
            params={"query": "SELECT * FROM v_leaky_secrets", "args": []},
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )
        with pytest.raises(ExecutorError, match="Unauthorized table or SQL operation"):
            executor.execute(env, dec)

    def test_trigger_accessing_unauthorized_table_blocked(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        _setup_security_test_db(db)
        executor = ScopedSQLiteExecutor(db)

        # Inserting into orders fires a trigger that mutates secrets
        env = build_envelope(
            tool="sql.execute",
            verb="write",
            resource=f"{executor.resource_id}#orders",
            params={
                "query": "INSERT INTO orders (id, item, amount) VALUES (?, ?, ?)",
                "args": [99, "trigger_item", 10.0],
            },
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )
        with pytest.raises(ExecutorError, match="Unauthorized table or SQL operation"):
            executor.execute(env, dec)

    def test_attach_and_detach_database_blocked(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        _setup_security_test_db(db)
        executor = ScopedSQLiteExecutor(db)

        env = build_envelope(
            tool="sql.execute",
            verb="admin",
            resource=f"{executor.resource_id}#orders",
            params={"query": "ATTACH DATABASE ':memory:' AS evil", "args": []},
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )
        with pytest.raises(ExecutorError, match="Forbidden SQLite administrative statement|ATTACH"):
            executor.execute(env, dec)

    def test_pragma_statements_blocked(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        _setup_security_test_db(db)
        executor = ScopedSQLiteExecutor(db)

        env = build_envelope(
            tool="sql.execute",
            verb="read",
            resource=f"{executor.resource_id}#orders",
            params={"query": "PRAGMA table_info(orders)", "args": []},
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )
        with pytest.raises(ExecutorError, match="PRAGMA statements are not permitted"):
            executor.execute(env, dec)

    def test_schema_ddl_blocked_by_default(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        _setup_security_test_db(db)
        executor = ScopedSQLiteExecutor(db)

        env = build_envelope(
            tool="sql.execute",
            verb="write",
            resource=f"{executor.resource_id}#orders",
            params={"query": "CREATE TABLE pwned (x INT)", "args": []},
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )
        with pytest.raises(ExecutorError, match="Unauthorized table or SQL operation"):
            executor.execute(env, dec)

    def test_case_insensitive_and_quoted_identifiers_supported(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        _setup_security_test_db(db)
        executor = ScopedSQLiteExecutor(db)

        for q in [
            'SELECT * FROM "orders"',
            "SELECT * FROM [orders]",
            "SELECT * FROM `orders`",
            "SELECT * FROM ORDERS",
        ]:
            env = build_envelope(
                tool="sql.execute",
                verb="read",
                resource=f"{executor.resource_id}#orders",
                params={"query": q, "args": []},
            )
            dec = Decision(
                verdict=Verdict.ALLOW,
                rule_id="r-allow",
                reason="allowed",
                policy_version="1",
                canonical_hash=env.canonical_hash,
            )
            res = executor.execute(env, dec)
            assert res["row_count"] == 2

    def test_multiple_authorized_tables_via_constraints(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        _setup_security_test_db(db)
        executor = ScopedSQLiteExecutor(db)

        # Allow both orders and audit_log via constraint
        env = build_envelope(
            tool="sql.execute",
            verb="read",
            resource=f"{executor.resource_id}#orders,audit_log",
            params={
                "query": "SELECT orders.id, audit_log.action FROM orders "
                "JOIN audit_log ON orders.id = audit_log.id",
                "args": [],
            },
        )
        dec = Decision(
            verdict=Verdict.ALLOW_WITH_CONSTRAINTS,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
            constraints={"allowed_tables": ["orders", "audit_log"]},
        )
        res = executor.execute(env, dec)
        assert res["row_count"] == 1
        assert res["rows"][0][1] == "initial_entry"


# ==============================================================================
# Filesystem Executor Security Tests (ACT-08)
# ==============================================================================


class TestFilesystemConfinementAndAtomicWrites:
    """Tests for ACT-08 atomic writes, descriptor verification, and confinement."""

    def test_atomic_write_preserves_target_on_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ws = tmp_path / "work"
        ws.mkdir()
        target = ws / "important.txt"
        target.write_text("ORIGINAL_CONTENT", encoding="utf-8")

        executor = LocalFSExecutor(ws)
        env = build_envelope(
            tool="fs.write",
            verb="write",
            resource=f"path:{executor.workspace_root}/important.txt",
            params={"content": "NEW_CORRUPTED_CONTENT"},
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )

        def failing_write(fd: int, data: bytes) -> int:
            raise OSError("Disk simulated write failure mid-transfer")

        monkeypatch.setattr(os, "write", failing_write)

        with pytest.raises(OSError, match="simulated write failure"):
            executor.execute(env, dec)

        # Target file must remain intact with original content
        assert target.read_text(encoding="utf-8") == "ORIGINAL_CONTENT"

        # Temporary files must have been cleaned up
        tmp_files = list(ws.glob(".actentra_tmp_*"))
        assert len(tmp_files) == 0

    def test_symlink_overwrite_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ws = tmp_path / "work"
        ws.mkdir()
        target = ws / "sym_file.txt"
        target.write_text("dummy", encoding="utf-8")

        executor = LocalFSExecutor(ws)
        env = build_envelope(
            tool="fs.write",
            verb="write",
            resource=f"path:{executor.workspace_root}/sym_file.txt",
            params={"content": "malicious overwrite"},
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )

        # Simulate target being a symlink
        monkeypatch.setattr(Path, "is_symlink", lambda self: True)

        with pytest.raises(ExecutorError, match="Cannot overwrite symlink"):
            executor.execute(env, dec)

    def test_ancestor_directory_escape_blocked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ws = tmp_path / "work"
        ws.mkdir()
        sub = ws / "deep" / "nested"
        sub.mkdir(parents=True)
        file_path = sub / "file.txt"
        file_path.write_text("hello", encoding="utf-8")

        outside = tmp_path / "outside"
        outside.mkdir()

        executor = LocalFSExecutor(ws)

        # Simulate deep nested directory resolving to outside directory
        real_realpath = os.path.realpath

        def fake_realpath(p: str | os.PathLike[str]) -> str:
            s = str(p)
            if "deep" in s.lower():
                return str(outside)
            return real_realpath(p)

        monkeypatch.setattr(os.path, "realpath", fake_realpath)

        env = build_envelope(
            tool="fs.read",
            verb="read",
            resource=f"path:{executor.workspace_root}/deep/nested/file.txt",
            params={},
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )

        match_pattern = (
            "escapes allowed base directory|"
            "escapes workspace boundary|"
            "blocked at execution boundary"
        )
        with pytest.raises(ExecutorError, match=match_pattern):
            executor.execute(env, dec)

    def test_post_open_descriptor_verification_blocks_escape(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ws = tmp_path / "work"
        ws.mkdir()
        target = ws / "leak.txt"
        target.write_text("secret_in_ws", encoding="utf-8")

        outside = tmp_path / "outside_leak.txt"
        outside.write_text("SECRET_OUTSIDE", encoding="utf-8")

        executor = LocalFSExecutor(ws)
        env = build_envelope(
            tool="fs.read",
            verb="read",
            resource=f"path:{executor.workspace_root}/leak.txt",
            params={},
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )

        # Simulate opened file descriptor resolving to outside file
        import actentra_executors.fs as fs_mod

        monkeypatch.setattr(fs_mod, "_get_fd_real_path", lambda fd: str(outside))

        match_pattern = (
            "escapes allowed base directory|"
            "escapes workspace boundary|"
            "blocked at execution boundary"
        )
        with pytest.raises(ExecutorError, match=match_pattern):
            executor.execute(env, dec)

    def test_read_rejects_directory_target(self, tmp_path: Path) -> None:
        ws = tmp_path / "work"
        ws.mkdir()
        sub = ws / "subdir"
        sub.mkdir()

        executor = LocalFSExecutor(ws)
        env = build_envelope(
            tool="fs.read",
            verb="read",
            resource=f"path:{executor.workspace_root}/subdir",
            params={},
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )

        with pytest.raises(ExecutorError, match="Target path is not a regular file"):
            executor.execute(env, dec)

    def test_write_and_delete_reject_root_path(self, tmp_path: Path) -> None:
        ws = tmp_path / "work"
        ws.mkdir()
        executor = LocalFSExecutor(ws)

        write_env = build_envelope(
            tool="fs.write",
            verb="write",
            resource=f"path:{executor.workspace_root}",
            params={"content": "fail"},
        )
        delete_env = build_envelope(
            tool="fs.delete",
            verb="delete",
            resource=f"path:{executor.workspace_root}",
            params={},
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="r-allow",
            reason="allowed",
            policy_version="1",
            canonical_hash=write_env.canonical_hash,
        )

        with pytest.raises(ExecutorError, match="Cannot overwrite workspace root"):
            executor.execute(write_env, dec)

        with pytest.raises(ExecutorError, match="Cannot delete workspace root"):
            executor.execute(delete_env, dec)
