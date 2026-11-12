"""Security and functional tests for ScopedSQLiteExecutor."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from actentra import ActionBlockedError, Boundary
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore, verify_log
from actentra_executors.fs import ExecutorError
from actentra_executors.sqlite import ScopedSQLiteExecutor, ScopedSQLiteTools


def _create_sample_db(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, item TEXT, amount REAL);")
        for idx in range(1, 6):
            conn.execute(
                "INSERT INTO orders (id, item, amount) VALUES (?, ?, ?);",
                (idx, f"item-{idx}", idx * 10.0),
            )
        conn.commit()
    finally:
        conn.close()


def test_sqlite_read_only_and_max_rows_constraints(tmp_path: Path) -> None:
    target_db = tmp_path / "orders.db"
    _create_sample_db(target_db)
    receipts_db = tmp_path / "receipts.db"

    executor = ScopedSQLiteExecutor(target_db)
    policy = load_policy_yaml(
        f"""
version: 1
defaults: {{ verdict: deny }}
rules:
  - id: sql-read-capped
    match: {{ tool: sql.execute, verb: read, resource: "{executor.resource_id}*" }}
    verdict: allow_with_constraints
    constraints:
      read_only: true
      max_rows: 2
  - id: sql-destructive-deny
    match: {{ tool: sql.execute, risk_any: [destructive, irreversible] }}
    verdict: deny
    reason: "Destructive SQL denied"
"""
    )
    boundary = Boundary(policy=policy, receipt_store=ReceiptStore(receipts_db), session_id="sql-1")
    tools = ScopedSQLiteTools(boundary, executor)

    res = tools.query("SELECT id, item FROM orders WHERE id >= ?", [1], table="orders")
    assert res["row_count"] == 2
    assert res["truncated"] is True
    assert res["columns"] == ["id", "item"]

    # Semicolon string literal inside parameterized arg works safely
    res2 = tools.query("SELECT id FROM orders WHERE item = ?", ["a; DROP TABLE orders"])
    assert res2["row_count"] == 0

    # Multi-statement SQL injection rejected
    with pytest.raises(ExecutorError, match="Multiple SQL statements"):
        tools.query("SELECT 1; SELECT 2")

    # SQL comments & ATTACH rejected
    with pytest.raises(ExecutorError, match="comments"):
        tools.query("SELECT 1 -- comment")

    with pytest.raises(ExecutorError, match="ATTACH"):
        tools.query("SELECT 1 WHERE 1=1 AND EXISTS (SELECT 1 FROM pragma_database_list) OR ATTACH")

    # Destructive SQL blocked by policy before executor runs
    with pytest.raises(ActionBlockedError):
        tools.query("DROP TABLE orders", table="orders")

    assert verify_log(receipts_db).ok is True


def test_sqlite_read_only_blocks_write_attempts(tmp_path: Path) -> None:
    target_db = tmp_path / "orders.db"
    _create_sample_db(target_db)
    receipts_db = tmp_path / "receipts.db"

    executor = ScopedSQLiteExecutor(target_db, read_only=True)
    policy = load_policy_yaml(
        f"""
version: 1
defaults: {{ verdict: deny }}
rules:
  - id: allow-sql
    match: {{ tool: sql.execute, resource: "{executor.resource_id}*" }}
    verdict: allow
"""
    )
    boundary = Boundary(policy=policy, receipt_store=ReceiptStore(receipts_db))
    tools = ScopedSQLiteTools(boundary, executor)

    with pytest.raises(ExecutorError, match="read_only"):
        tools.query("INSERT INTO orders (id, item, amount) VALUES (?, ?, ?)", [99, "x", 1.0])

    assert verify_log(receipts_db).ok is True
