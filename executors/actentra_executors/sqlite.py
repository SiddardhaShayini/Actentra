"""Narrowly scoped, parameterized SQLite executor for Actentra."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

from actentra.boundary import Boundary
from actentra_core.canonicalize import canonicalize_windows_path
from actentra_core.envelope import ActionEnvelope, ProvenanceItem
from actentra_core.verdict import Decision
from actentra_executors.fs import ExecutorError

_DEFAULT_MAX_ROWS = 200
_FORBIDDEN_SQL_RE = re.compile(
    r"\b(attach|detach|vacuum|load_extension|reindex)\b",
    re.IGNORECASE,
)

_ALWAYS_DENIED_ACTIONS: frozenset[int] = frozenset({
    sqlite3.SQLITE_ATTACH,       # 24: ATTACH DATABASE
    sqlite3.SQLITE_DETACH,       # 25: DETACH DATABASE
    sqlite3.SQLITE_PRAGMA,       # 19: PRAGMA statements and pragma_* table queries
    sqlite3.SQLITE_REINDEX,      # 27: REINDEX
    sqlite3.SQLITE_ANALYZE,      # 28: ANALYZE
})

_MUTATION_ACTIONS: frozenset[int] = frozenset({
    sqlite3.SQLITE_INSERT,       # 18
    sqlite3.SQLITE_UPDATE,       # 23
    sqlite3.SQLITE_DELETE,       # 9
})

_SCHEMA_ACTIONS: frozenset[int] = frozenset({
    sqlite3.SQLITE_CREATE_INDEX,         # 1
    sqlite3.SQLITE_CREATE_TABLE,         # 2
    sqlite3.SQLITE_CREATE_TEMP_INDEX,    # 3
    sqlite3.SQLITE_CREATE_TEMP_TABLE,    # 4
    sqlite3.SQLITE_CREATE_TEMP_TRIGGER,  # 5
    sqlite3.SQLITE_CREATE_TEMP_VIEW,     # 6
    sqlite3.SQLITE_CREATE_TRIGGER,       # 7
    sqlite3.SQLITE_CREATE_VIEW,          # 8
    sqlite3.SQLITE_DROP_INDEX,           # 10
    sqlite3.SQLITE_DROP_TABLE,           # 11
    sqlite3.SQLITE_DROP_TEMP_INDEX,      # 12
    sqlite3.SQLITE_DROP_TEMP_TABLE,      # 13
    sqlite3.SQLITE_DROP_TEMP_TRIGGER,    # 14
    sqlite3.SQLITE_DROP_TEMP_VIEW,       # 15
    sqlite3.SQLITE_DROP_TRIGGER,         # 16
    sqlite3.SQLITE_DROP_VIEW,            # 17
    sqlite3.SQLITE_ALTER_TABLE,          # 26
    sqlite3.SQLITE_CREATE_VTABLE,        # 29
    sqlite3.SQLITE_DROP_VTABLE,          # 30
})

_TABLE_ACCESS_ACTIONS: frozenset[int] = frozenset({
    sqlite3.SQLITE_READ,                 # 20
    sqlite3.SQLITE_INSERT,               # 18
    sqlite3.SQLITE_UPDATE,               # 23
    sqlite3.SQLITE_DELETE,               # 9
})

_FORBIDDEN_FUNCTIONS: frozenset[str] = frozenset({"load_extension", "fts3_tokenizer"})


def _validate_single_statement(sql: str) -> str:
    """Validate that SQL contains exactly one statement and no dangerous SQLite commands."""
    if not isinstance(sql, str) or not sql.strip():
        raise ExecutorError("SQL query must be a non-empty string")

    # Reject C-style block comments and SQL line comments to prevent parser differentials.
    if "/*" in sql or "--" in sql:
        raise ExecutorError("SQL comments (-- or /* */) are not permitted")

    in_single = False
    in_double = False
    i = 0
    semi_pos: int | None = None
    length = len(sql)
    while i < length:
        ch = sql[i]
        if ch == "'" and not in_double:
            if in_single and i + 1 < length and sql[i + 1] == "'":
                i += 2
                continue
            in_single = not in_single
        elif ch == '"' and not in_single:
            if in_double and i + 1 < length and sql[i + 1] == '"':
                i += 2
                continue
            in_double = not in_double
        elif ch == ";" and not in_single and not in_double:
            if semi_pos is not None:
                raise ExecutorError("Multiple SQL statements are not permitted")
            semi_pos = i
        i += 1

    if in_single or in_double:
        raise ExecutorError("Unterminated string literal in SQL query")

    if semi_pos is not None and sql[semi_pos + 1 :].strip():
        raise ExecutorError("Multiple SQL statements are not permitted")

    clean = sql[:semi_pos].strip() if semi_pos is not None else sql.strip()
    if not clean:
        raise ExecutorError("SQL query must be non-empty")

    if _FORBIDDEN_SQL_RE.search(clean):
        raise ExecutorError("Forbidden SQLite administrative statement (ATTACH/DETACH/VACUUM)")

    if re.match(r"^\s*pragma\b", clean, re.IGNORECASE):
        raise ExecutorError("PRAGMA statements are not permitted")

    return clean


def _scan_cte_main_verb(sql: str) -> str:
    """Extract and classify the main statement verb following a CTE (WITH ...).

    Scans through CTE definitions to locate the primary statement verb (e.g. SELECT vs DELETE).
    Defaults to 'other' if parsing fails or statement shape is unknown (fail closed).
    """
    i = 0
    n = len(sql)

    def skip_whitespace_and_comments() -> None:
        nonlocal i
        while i < n:
            if sql[i].isspace():
                i += 1
            elif sql[i : i + 2] == "--":
                i += 2
                while i < n and sql[i] != "\n":
                    i += 1
            elif sql[i : i + 2] == "/*":
                i += 2
                while i < n and sql[i : i + 2] != "*/":
                    i += 1
                i += 2
            else:
                break

    skip_whitespace_and_comments()
    if not sql[i:].upper().startswith("WITH"):
        return "other"
    i += 4

    skip_whitespace_and_comments()
    if sql[i:].upper().startswith("RECURSIVE"):
        i += 9

    # Scan one or more CTE definitions: name [(...)] AS ( ... ) [, ...]
    while i < n:
        skip_whitespace_and_comments()
        if i >= n:
            return "other"

        # Scan until AS keyword
        found_as = False
        while i < n:
            skip_whitespace_and_comments()
            if i >= n:
                return "other"
            if sql[i] in ("'", '"'):
                quote = sql[i]
                i += 1
                while i < n and sql[i] != quote:
                    if sql[i] == "\\" and i + 1 < n:
                        i += 1
                    i += 1
                if i < n:
                    i += 1
                continue
            if sql[i : i + 2].upper() == "AS" and (
                i + 2 >= n or not (sql[i + 2].isalnum() or sql[i + 2] == "_")
            ):
                i += 2
                found_as = True
                break
            i += 1

        if not found_as:
            return "other"

        skip_whitespace_and_comments()
        if i >= n or sql[i] != "(":
            return "other"
        i += 1

        # Track paren depth to find closing ')'
        depth = 1
        while i < n and depth > 0:
            if sql[i] in ("'", '"'):
                quote = sql[i]
                i += 1
                while i < n and sql[i] != quote:
                    if sql[i] == "\\" and i + 1 < n:
                        i += 1
                    i += 1
                if i < n:
                    i += 1
                continue
            if sql[i : i + 2] == "--":
                i += 2
                while i < n and sql[i] != "\n":
                    i += 1
                continue
            if sql[i : i + 2] == "/*":
                i += 2
                while i < n and sql[i : i + 2] != "*/":
                    i += 1
                i += 2
                continue
            if sql[i] == "(":
                depth += 1
            elif sql[i] == ")":
                depth -= 1
            i += 1

        if depth != 0:
            return "other"

        skip_whitespace_and_comments()
        if i < n and sql[i] == ",":
            i += 1
            continue
        break

    skip_whitespace_and_comments()
    if i >= n:
        return "other"

    token_match = re.match(r"^[A-Za-z_]+", sql[i:])
    if not token_match:
        return "other"

    main_verb = token_match.group(0).upper()
    if main_verb in ("SELECT", "EXPLAIN"):
        return "read"
    if main_verb in ("DELETE", "DROP", "TRUNCATE"):
        return "delete"
    if main_verb in ("INSERT", "UPDATE", "REPLACE", "CREATE", "ALTER"):
        return "write"
    return "other"


def _infer_verb(sql: str) -> str:
    first = sql.lstrip().split(None, 1)[0].upper()
    if first == "WITH":
        return _scan_cte_main_verb(sql)
    if first in ("SELECT", "EXPLAIN"):
        return "read"
    if first in ("DELETE", "DROP", "TRUNCATE"):
        return "delete"
    if first in ("INSERT", "UPDATE", "REPLACE", "CREATE", "ALTER"):
        return "write"
    return "other"


class ScopedSQLiteExecutor:
    """Parameterized SQLite executor pinned to one database file."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        read_only: bool = False,
        default_max_rows: int = _DEFAULT_MAX_ROWS,
    ) -> None:
        raw = str(Path(db_path).resolve())
        self._db_canon = canonicalize_windows_path(raw, resolve_fs=True)
        self._db_path = Path(self._db_canon.replace("/", "\\"))
        self._read_only = read_only
        self._default_max_rows = default_max_rows

    @property
    def resource_id(self) -> str:
        return f"sqlite:///{self._db_canon}"

    def execute(self, envelope: ActionEnvelope, decision: Decision) -> dict[str, Any]:
        """Execute an authorized, parameterized single SQL statement."""
        if envelope.action.tool != "sql.execute":
            raise ExecutorError(f"Unsupported tool for SQLite executor: {envelope.action.tool!r}")

        expected_prefix = self.resource_id
        res = envelope.action.resource
        if res != expected_prefix and not res.startswith(f"{expected_prefix}#"):
            raise ExecutorError(
                f"SQLite resource {res!r} does not match bound database {expected_prefix!r}"
            )

        params = envelope.action.params
        raw_query = params.get("query")
        if not isinstance(raw_query, str):
            raise ExecutorError("sql.execute requires string 'query' parameter")
        sql = _validate_single_statement(raw_query)

        args = params.get("args", [])
        if not isinstance(args, (list, dict)):
            raise ExecutorError("sql.execute 'args' must be a list or dict")

        constraints = dict(decision.constraints)
        effective_ro = self._read_only or bool(constraints.get("read_only", False))
        verb = _infer_verb(sql)
        if effective_ro and verb != "read":
            raise ExecutorError("Constraint violation: read_only mode permits SELECT queries only")

        max_rows = int(constraints.get("max_rows", self._default_max_rows))
        if max_rows < 1:
            raise ExecutorError("max_rows constraint must be >= 1")

        authorized_tables: set[str] | None = None
        if "#" in res:
            fragment = res.split("#", 1)[1].strip()
            if fragment:
                authorized_tables = {t.strip().lower() for t in fragment.split(",") if t.strip()}
            else:
                authorized_tables = set()

        constraint_tables = constraints.get("allowed_tables")
        if constraint_tables is not None:
            if isinstance(constraint_tables, str):
                c_set = {t.strip().lower() for t in constraint_tables.split(",") if t.strip()}
            elif isinstance(constraint_tables, (list, tuple, set)):
                c_set = {str(t).strip().lower() for t in constraint_tables if str(t).strip()}
            else:
                c_set = set()
            authorized_tables = (
                c_set if authorized_tables is None else authorized_tables & c_set
            )

        param_table = params.get("table")
        if isinstance(param_table, str) and param_table.strip():
            p_set = {param_table.strip().lower()}
            authorized_tables = (
                p_set if authorized_tables is None else authorized_tables & p_set
            )

        allow_ddl = bool(constraints.get("allow_ddl", False))

        def _authorizer(
            action: int,
            arg1: str | None,
            arg2: str | None,
            db_name: str | None,
            trigger_or_view: str | None,
        ) -> int:
            if action in _ALWAYS_DENIED_ACTIONS:
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_FUNCTION and arg2 and arg2.lower() in _FORBIDDEN_FUNCTIONS:
                return sqlite3.SQLITE_DENY
            if effective_ro and action in _MUTATION_ACTIONS:
                return sqlite3.SQLITE_DENY
            if (not allow_ddl or effective_ro) and action in _SCHEMA_ACTIONS:
                return sqlite3.SQLITE_DENY
            if (
                authorized_tables is not None
                and action in _TABLE_ACCESS_ACTIONS
                and arg1 is not None
                and arg1.lower() not in authorized_tables
            ):
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        if effective_ro:
            uri = f"{self._db_path.as_uri()}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=5.0)
            conn.execute("PRAGMA query_only = ON;")
        else:
            conn = sqlite3.connect(self._db_path, timeout=5.0)

        conn.set_authorizer(_authorizer)

        try:
            cur = conn.execute(sql, args)
            if verb == "read":
                rows = cur.fetchmany(max_rows + 1)
                truncated = len(rows) > max_rows
                if truncated:
                    rows = rows[:max_rows]
                columns = [desc[0] for desc in (cur.description or ())]
                return {
                    "columns": columns,
                    "rows": [list(r) for r in rows],
                    "row_count": len(rows),
                    "truncated": truncated,
                }
            conn.commit()
            return {
                "rowcount": cur.rowcount,
                "lastrowid": cur.lastrowid,
            }
        except sqlite3.Error as exc:
            msg = str(exc).lower()
            if "prohibited" in msg or "not authorized" in msg:
                raise ExecutorError(f"Unauthorized table or SQL operation: {exc}") from exc
            raise ExecutorError(f"SQLite execution error ({type(exc).__name__})") from exc
        finally:
            conn.close()


class ScopedSQLiteTools:
    """Agent-facing parameterized SQLite interface bound through Actentra Boundary."""

    def __init__(self, boundary: Boundary, executor: ScopedSQLiteExecutor) -> None:
        self._boundary = boundary
        self._executor = executor

    def query(
        self,
        sql: str,
        args: list[Any] | dict[str, Any] | None = None,
        *,
        table: str | None = None,
        provenance: list[ProvenanceItem] | tuple[ProvenanceItem, ...] = (),
        user_goal: str | None = None,
    ) -> dict[str, Any]:
        clean_sql = sql.strip()
        verb = _infer_verb(clean_sql) if clean_sql else "other"
        resource = f"{self._executor.resource_id}#{table}" if table else self._executor.resource_id
        result: dict[str, Any] = self._boundary.execute(
            tool="sql.execute",
            verb=verb,
            resource=resource,
            params={"query": sql, "args": args if args is not None else []},
            fn=self._executor.execute,
            provenance=provenance,
            user_goal=user_goal,
        )
        return result
