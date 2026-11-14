"""Tamper-evident, hash-chained SQLite receipt log for Actentra."""

from __future__ import annotations

import contextlib
import json
import sqlite3
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from actentra_core.canonicalize import canonicalize_json, hash_canonical
from actentra_core.envelope import (
    ActionEnvelope,
    ActionSpec,
    compute_action_hash,
    utc_now_iso,
)
from actentra_core.verdict import Decision

GENESIS_HASH = "sha256:" + ("0" * 64)
OutcomeStatus = Literal["success", "failure", "unknown"]
_VALID_OUTCOMES = frozenset({"success", "failure", "unknown"})


class ReceiptError(RuntimeError):
    """Raised when a durable receipt record cannot be committed or verified."""


@dataclass(frozen=True, slots=True)
class ReceiptRecord:
    seq: int
    record_type: Literal["decision", "outcome"]
    crossing_id: str
    session_id: str
    canonical_hash: str
    policy_version: str
    verdict: str | None
    rule_id: str | None
    reason: str | None
    risk_tags: tuple[str, ...]
    shadow: bool
    status: str | None
    result_hash: str | None
    error: str | None
    ts: str
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "record_type": self.record_type,
            "crossing_id": self.crossing_id,
            "session_id": self.session_id,
            "canonical_hash": self.canonical_hash,
            "policy_version": self.policy_version,
            "verdict": self.verdict,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "risk_tags": list(self.risk_tags),
            "shadow": self.shadow,
            "status": self.status,
            "result_hash": self.result_hash,
            "error": self.error,
            "ts": self.ts,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


PendingApprovalStatus = Literal["pending", "approved", "rejected", "expired", "consumed"]
_VALID_PENDING_STATUSES = frozenset({"pending", "approved", "rejected", "expired", "consumed"})


@dataclass(frozen=True, slots=True)
class PendingApprovalRecord:
    crossing_id: str
    session_id: str
    canonical_hash: str
    tool: str
    verb: str
    resource: str
    risk_tags: tuple[str, ...]
    reason: str
    params: dict[str, Any]
    ts: str
    expires_at: float
    status: PendingApprovalStatus
    resolution_ts: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "crossing_id": self.crossing_id,
            "session_id": self.session_id,
            "canonical_hash": self.canonical_hash,
            "tool": self.tool,
            "verb": self.verb,
            "resource": self.resource,
            "risk_tags": list(self.risk_tags),
            "reason": self.reason,
            "params": self.params,
            "ts": self.ts,
            "expires_at": self.expires_at,
            "expires_in_seconds": max(0.0, round(self.expires_at - time.time(), 1)),
            "status": self.status,
            "resolution_ts": self.resolution_ts,
        }


@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    total_records: int
    last_hash: str
    errors: tuple[str, ...] = ()


def _compute_entry_hash(
    *,
    seq: int,
    record_type: str,
    crossing_id: str,
    session_id: str,
    canonical_hash: str,
    policy_version: str,
    verdict: str | None,
    rule_id: str | None,
    reason: str | None,
    risk_tags: list[str] | tuple[str, ...],
    shadow: bool,
    status: str | None,
    result_hash: str | None,
    error: str | None,
    ts: str,
    prev_hash: str,
) -> str:
    payload = {
        "seq": seq,
        "record_type": record_type,
        "crossing_id": crossing_id,
        "session_id": session_id,
        "canonical_hash": canonical_hash,
        "policy_version": policy_version,
        "verdict": verdict,
        "rule_id": rule_id,
        "reason": reason,
        "risk_tags": list(risk_tags),
        "shadow": shadow,
        "status": status,
        "result_hash": result_hash,
        "error": error,
        "ts": ts,
        "prev_hash": prev_hash,
    }
    return hash_canonical(payload)


class ReceiptStore:
    """Append-only SQLite WAL receipt store with SHA-256 hash chaining."""

    def __init__(self, db_path: str | Path, *, synchronous: str = "FULL") -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._synchronous = synchronous if synchronous in ("FULL", "NORMAL", "EXTRA") else "FULL"
        self._init_db()

    @property
    def db_path(self) -> Path:
        return self._db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute(f"PRAGMA synchronous={self._synchronous};")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS receipts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_type TEXT NOT NULL CHECK (record_type IN ('decision', 'outcome')),
                    crossing_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    canonical_hash TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    verdict TEXT,
                    rule_id TEXT,
                    reason TEXT,
                    risk_tags_json TEXT NOT NULL,
                    shadow INTEGER NOT NULL DEFAULT 0,
                    status TEXT CHECK (
                        status IN ('success', 'failure', 'unknown') OR status IS NULL
                    ),
                    result_hash TEXT,
                    error TEXT,
                    ts TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_receipts_crossing ON receipts(crossing_id);"
            )
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_unique_outcome
                ON receipts(crossing_id)
                WHERE record_type = 'outcome';
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS action_envelopes (
                    crossing_id TEXT PRIMARY KEY,
                    envelope_json TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pending_approvals (
                    crossing_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    canonical_hash TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    verb TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    risk_tags_json TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    params_json TEXT NOT NULL,
                    ts TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('pending', 'approved', 'rejected', 'expired', 'consumed')
                    ),
                    resolution_ts TEXT
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_approvals(status);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_pending_expires ON pending_approvals(expires_at);"
            )
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to initialize receipt store: {exc}") from exc
        finally:
            conn.close()

    def _append_record(
        self,
        *,
        record_type: Literal["decision", "outcome"],
        crossing_id: str,
        session_id: str,
        canonical_hash: str,
        policy_version: str,
        verdict: str | None,
        rule_id: str | None,
        reason: str | None,
        risk_tags: tuple[str, ...],
        shadow: bool,
        status: OutcomeStatus | None,
        result_hash: str | None,
        error: str | None,
        ts: str | None = None,
        envelope: ActionEnvelope | None = None,
    ) -> ReceiptRecord:
        stamp = ts or utc_now_iso()
        risk_json = canonicalize_json(list(risk_tags))
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            if record_type == "outcome":
                existing = conn.execute(
                    "SELECT seq FROM receipts "
                    "WHERE crossing_id = ? AND record_type = 'outcome' LIMIT 1;",
                    (crossing_id,),
                ).fetchone()
                if existing is not None:
                    raise ReceiptError(f"Outcome already recorded for crossing '{crossing_id}'")

            row = conn.execute(
                "SELECT seq, entry_hash FROM receipts ORDER BY seq DESC LIMIT 1;"
            ).fetchone()
            if row is None:
                next_seq = 1
                prev_hash = GENESIS_HASH
            else:
                next_seq = int(row[0]) + 1
                prev_hash = str(row[1])

            entry_hash = _compute_entry_hash(
                seq=next_seq,
                record_type=record_type,
                crossing_id=crossing_id,
                session_id=session_id,
                canonical_hash=canonical_hash,
                policy_version=policy_version,
                verdict=verdict,
                rule_id=rule_id,
                reason=reason,
                risk_tags=risk_tags,
                shadow=shadow,
                status=status,
                result_hash=result_hash,
                error=error,
                ts=stamp,
                prev_hash=prev_hash,
            )

            conn.execute(
                """
                INSERT INTO receipts (
                    seq, record_type, crossing_id, session_id, canonical_hash,
                    policy_version, verdict, rule_id, reason, risk_tags_json,
                    shadow, status, result_hash, error, ts, prev_hash, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    next_seq,
                    record_type,
                    crossing_id,
                    session_id,
                    canonical_hash,
                    policy_version,
                    verdict,
                    rule_id,
                    reason,
                    risk_json,
                    1 if shadow else 0,
                    status,
                    result_hash,
                    error,
                    stamp,
                    prev_hash,
                    entry_hash,
                ),
            )
            if envelope is not None:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO action_envelopes (
                        crossing_id, envelope_json
                    ) VALUES (?, ?);
                    """,
                    (envelope.crossing_id, canonicalize_json(envelope.to_dict())),
                )
            conn.execute("COMMIT;")
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            if "UNIQUE constraint failed" in str(exc) and record_type == "outcome":
                raise ReceiptError(
                    f"Outcome already recorded for crossing '{crossing_id}'"
                ) from exc
            raise ReceiptError(f"Failed to commit receipt record: {exc}") from exc
        except Exception:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

        return ReceiptRecord(
            seq=next_seq,
            record_type=record_type,
            crossing_id=crossing_id,
            session_id=session_id,
            canonical_hash=canonical_hash,
            policy_version=policy_version,
            verdict=verdict,
            rule_id=rule_id,
            reason=reason,
            risk_tags=risk_tags,
            shadow=shadow,
            status=status,
            result_hash=result_hash,
            error=error,
            ts=stamp,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

    def record_decision(
        self, envelope: ActionEnvelope, decision: Decision
    ) -> ReceiptRecord:
        """Persist an immutable decision record and envelope atomically (I5)."""
        return self._append_record(
            record_type="decision",
            crossing_id=envelope.crossing_id,
            session_id=envelope.session_id,
            canonical_hash=envelope.canonical_hash,
            policy_version=decision.policy_version,
            verdict=decision.verdict.value,
            rule_id=decision.rule_id,
            reason=decision.reason[:1000],
            risk_tags=decision.risk_tags,
            shadow=decision.shadow,
            status=None,
            result_hash=None,
            error=None,
            ts=envelope.ts,
            envelope=envelope,
        )

    def get_envelope(
        self, crossing_id: str, *, verify_integrity: bool = True
    ) -> dict[str, Any] | None:
        """Retrieve stored envelope payload for a crossing if available.

        If verify_integrity is True, checks that the stored action payload's
        recomputed canonical hash matches the recorded canonical_hash.
        """
        conn = self._connect()
        try:
            cur = conn.execute(
                "SELECT envelope_json FROM action_envelopes WHERE crossing_id = ?;",
                (crossing_id,),
            )
            row = cur.fetchone()
            if row and row[0]:
                data = json.loads(row[0])
                if not isinstance(data, dict):
                    return None
                if verify_integrity and "canonical_hash" in data:
                    action_data = data.get("action")
                    agent_data = data.get("agent")
                    if isinstance(action_data, dict) and isinstance(agent_data, dict):
                        act_spec = ActionSpec(
                            tool=str(action_data.get("tool", "")),
                            verb=str(action_data.get("verb", "other")),
                            resource=str(action_data.get("resource", "")),
                            params=action_data.get("params") or {},
                            idempotency_key=action_data.get("idempotency_key"),
                        )
                        computed = compute_action_hash(
                            envelope_version=str(data.get("envelope_version", "1")),
                            session_id=str(data.get("session_id", "")),
                            agent_id=str(agent_data.get("id", "")),
                            action=act_spec,
                        )
                        if computed != data["canonical_hash"]:
                            return None
                return data
            return None
        except sqlite3.Error:
            return None
        finally:
            conn.close()

    def record_outcome(
        self,
        *,
        crossing_id: str,
        session_id: str,
        canonical_hash: str,
        policy_version: str,
        status: OutcomeStatus,
        result_hash: str | None = None,
        error: str | None = None,
        reason: str | None = None,
    ) -> ReceiptRecord:
        """Append an immutable post-execution outcome record (success, failure, or unknown)."""
        if status not in _VALID_OUTCOMES:
            raise ReceiptError(f"Invalid outcome status: {status!r}")
        safe_error = error[:1000] if error is not None else None
        safe_reason = reason[:1000] if reason is not None else None
        return self._append_record(
            record_type="outcome",
            crossing_id=crossing_id,
            session_id=session_id,
            canonical_hash=canonical_hash,
            policy_version=policy_version,
            verdict=None,
            rule_id=None,
            reason=safe_reason,
            risk_tags=(),
            shadow=False,
            status=status,
            result_hash=result_hash,
            error=safe_error,
        )

    def get_decision_receipt(self, crossing_id: str) -> ReceiptRecord | None:
        """Fetch the decision receipt record for a crossing_id if one exists."""
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT seq, record_type, crossing_id, session_id, canonical_hash,
                       policy_version, verdict, rule_id, reason, risk_tags_json,
                       shadow, status, result_hash, error, ts, prev_hash, entry_hash
                FROM receipts
                WHERE crossing_id = ? AND record_type = 'decision'
                ORDER BY seq DESC LIMIT 1;
                """,
                (crossing_id,),
            ).fetchone()
            if row is None:
                return None
            risk_list = json.loads(str(row[9]))
            return ReceiptRecord(
                seq=int(row[0]),
                record_type="decision",
                crossing_id=str(row[2]),
                session_id=str(row[3]),
                canonical_hash=str(row[4]),
                policy_version=str(row[5]),
                verdict=str(row[6]) if row[6] is not None else None,
                rule_id=str(row[7]) if row[7] is not None else None,
                reason=str(row[8]) if row[8] is not None else None,
                risk_tags=tuple(str(t) for t in risk_list),
                shadow=bool(row[10]),
                status=str(row[11]) if row[11] is not None else None,
                result_hash=str(row[12]) if row[12] is not None else None,
                error=str(row[13]) if row[13] is not None else None,
                ts=str(row[14]),
                prev_hash=str(row[15]),
                entry_hash=str(row[16]),
            )
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to fetch decision receipt: {exc}") from exc
        finally:
            conn.close()

    def has_outcome_receipt(self, crossing_id: str) -> bool:
        """Return True if an outcome receipt already exists for crossing_id."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT 1 FROM receipts WHERE crossing_id = ? AND record_type = 'outcome' LIMIT 1;",
                (crossing_id,),
            ).fetchone()
            return row is not None
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to check outcome receipt: {exc}") from exc
        finally:
            conn.close()

    def recover_pending_outcomes(self) -> list[ReceiptRecord]:
        """Mark interrupted execution decisions without outcome records as ``unknown``."""
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT d.crossing_id, d.session_id, d.canonical_hash, d.policy_version
                FROM receipts d
                WHERE d.record_type = 'decision'
                  AND d.verdict IN ('allow', 'allow_with_constraints')
                  AND NOT EXISTS (
                      SELECT 1 FROM receipts o
                      WHERE o.crossing_id = d.crossing_id
                        AND o.record_type = 'outcome'
                  )
                ORDER BY d.seq ASC;
                """
            ).fetchall()
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to scan pending outcomes: {exc}") from exc
        finally:
            conn.close()

        recovered: list[ReceiptRecord] = []
        for crossing_id, session_id, canonical_hash, policy_version in rows:
            rec = self.record_outcome(
                crossing_id=str(crossing_id),
                session_id=str(session_id),
                canonical_hash=str(canonical_hash),
                policy_version=str(policy_version),
                status="unknown",
                error="Recovered interrupted execution without outcome record",
            )
            recovered.append(rec)
        return recovered

    def iter_records_stream(
        self,
        *,
        chunk_size: int = 500,
        start_seq: int = 1,
        reverse: bool = False,
    ) -> Iterator[ReceiptRecord]:
        """Yield stored receipt records in bounded chunks without loading the entire DB."""
        effective_chunk = max(1, chunk_size)
        conn = self._connect()
        try:
            cursor = conn.cursor()
            if reverse:
                cursor.execute(
                    """
                    SELECT seq, record_type, crossing_id, session_id, canonical_hash,
                           policy_version, verdict, rule_id, reason, risk_tags_json,
                           shadow, status, result_hash, error, ts, prev_hash, entry_hash
                    FROM receipts
                    WHERE seq <= ?
                    ORDER BY seq DESC;
                    """,
                    (start_seq if start_seq > 1 else 999999999999,),
                )
            else:
                cursor.execute(
                    """
                    SELECT seq, record_type, crossing_id, session_id, canonical_hash,
                           policy_version, verdict, rule_id, reason, risk_tags_json,
                           shadow, status, result_hash, error, ts, prev_hash, entry_hash
                    FROM receipts
                    WHERE seq >= ?
                    ORDER BY seq ASC;
                    """,
                    (start_seq,),
                )

            while True:
                rows = cursor.fetchmany(effective_chunk)
                if not rows:
                    break
                for row in rows:
                    risk_list = json.loads(str(row[9]))
                    rec_type: Literal["decision", "outcome"] = (
                        "decision" if row[1] == "decision" else "outcome"
                    )
                    yield ReceiptRecord(
                        seq=int(row[0]),
                        record_type=rec_type,
                        crossing_id=str(row[2]),
                        session_id=str(row[3]),
                        canonical_hash=str(row[4]),
                        policy_version=str(row[5]),
                        verdict=str(row[6]) if row[6] is not None else None,
                        rule_id=str(row[7]) if row[7] is not None else None,
                        reason=str(row[8]) if row[8] is not None else None,
                        risk_tags=tuple(str(t) for t in risk_list),
                        shadow=bool(row[10]),
                        status=str(row[11]) if row[11] is not None else None,
                        result_hash=str(row[12]) if row[12] is not None else None,
                        error=str(row[13]) if row[13] is not None else None,
                        ts=str(row[14]),
                        prev_hash=str(row[15]),
                        entry_hash=str(row[16]),
                    )
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to stream receipt records: {exc}") from exc
        finally:
            conn.close()

    def iter_records(self) -> list[ReceiptRecord]:
        """Return all stored receipt records in sequence order."""
        return list(self.iter_records_stream())

    def archive_records(
        self,
        *,
        before_seq: int,
        archive_db_path: str | Path,
        delete_from_source: bool = False,
    ) -> int:
        """Archive records older than before_seq to a target archive SQLite database.

        Preserves action envelopes, receipts, and hash chain.
        Returns the number of receipt records archived.
        """
        if before_seq <= 1:
            return 0

        archive_store = ReceiptStore(archive_db_path)
        source_conn = self._connect()
        archive_conn = archive_store._connect()

        try:
            # Read rows to archive
            rows = source_conn.execute(
                """
                SELECT seq, record_type, crossing_id, session_id, canonical_hash,
                       policy_version, verdict, rule_id, reason, risk_tags_json,
                       shadow, status, result_hash, error, ts, prev_hash, entry_hash
                FROM receipts
                WHERE seq < ?
                ORDER BY seq ASC;
                """,
                (before_seq,),
            ).fetchall()

            if not rows:
                return 0

            crossing_ids = list({str(r[2]) for r in rows})
            placeholders = ",".join("?" for _ in crossing_ids)

            envelope_rows = source_conn.execute(
                f"""
                SELECT crossing_id, envelope_json
                FROM action_envelopes
                WHERE crossing_id IN ({placeholders});
                """,  # noqa: S608
                crossing_ids,
            ).fetchall()

            with archive_conn:
                archive_conn.executemany(
                    """
                    INSERT OR REPLACE INTO action_envelopes
                        (crossing_id, envelope_json)
                    VALUES (?, ?);
                    """,
                    envelope_rows,
                )
                archive_conn.executemany(
                    """
                    INSERT OR REPLACE INTO receipts
                        (seq, record_type, crossing_id, session_id, canonical_hash,
                         policy_version, verdict, rule_id, reason, risk_tags_json,
                         shadow, status, result_hash, error, ts, prev_hash, entry_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    rows,
                )

            if delete_from_source:
                with source_conn:
                    source_conn.execute("DELETE FROM receipts WHERE seq < ?;", (before_seq,))
                    source_conn.execute(
                        f"DELETE FROM action_envelopes WHERE crossing_id IN ({placeholders});",  # noqa: S608
                        crossing_ids,
                    )

            return len(rows)
        except sqlite3.Error as exc:
            raise ReceiptError(f"Archival failed: {exc}") from exc
        finally:
            source_conn.close()
            archive_conn.close()

    def get_latest_record(self) -> ReceiptRecord | None:
        """Fetch the most recent receipt record without scanning entire log."""
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT seq, record_type, crossing_id, session_id, canonical_hash,
                       policy_version, verdict, rule_id, reason, risk_tags_json,
                       shadow, status, result_hash, error, ts, prev_hash, entry_hash
                FROM receipts
                ORDER BY seq DESC LIMIT 1;
                """
            ).fetchone()
            if row is None:
                return None
            risk_list = json.loads(str(row[9]))
            rec_type: Literal["decision", "outcome"] = (
                "decision" if row[1] == "decision" else "outcome"
            )
            return ReceiptRecord(
                seq=int(row[0]),
                record_type=rec_type,
                crossing_id=str(row[2]),
                session_id=str(row[3]),
                canonical_hash=str(row[4]),
                policy_version=str(row[5]),
                verdict=str(row[6]) if row[6] is not None else None,
                rule_id=str(row[7]) if row[7] is not None else None,
                reason=str(row[8]) if row[8] is not None else None,
                risk_tags=tuple(str(t) for t in risk_list),
                shadow=bool(row[10]),
                status=str(row[11]) if row[11] is not None else None,
                result_hash=str(row[12]) if row[12] is not None else None,
                error=str(row[13]) if row[13] is not None else None,
                ts=str(row[14]),
                prev_hash=str(row[15]),
                entry_hash=str(row[16]),
            )
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to fetch latest record: {exc}") from exc
        finally:
            conn.close()

    def record_count(self) -> int:
        """Return total count of persisted receipt records."""
        conn = self._connect()
        try:
            return int(conn.execute("SELECT COUNT(*) FROM receipts;").fetchone()[0])
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to count receipt records: {exc}") from exc
        finally:
            conn.close()

    def add_pending_approval(
        self,
        *,
        envelope: ActionEnvelope,
        decision: Decision,
        ttl_seconds: float = 300.0,
    ) -> PendingApprovalRecord:
        """Persist a pending approval in SQLite WAL surviving process restarts."""
        now = time.time()
        expires_at = now + ttl_seconds
        risk_json = canonicalize_json(list(decision.risk_tags))
        params_json = canonicalize_json(envelope.action.params)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute(
                """
                INSERT OR REPLACE INTO pending_approvals (
                    crossing_id, session_id, canonical_hash, tool, verb,
                    resource, risk_tags_json, reason, params_json, ts,
                    expires_at, status, resolution_ts
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL);
                """,
                (
                    envelope.crossing_id,
                    envelope.session_id,
                    envelope.canonical_hash,
                    envelope.action.tool,
                    envelope.action.verb,
                    envelope.action.resource,
                    risk_json,
                    decision.reason[:1000],
                    params_json,
                    envelope.ts,
                    expires_at,
                ),
            )
            conn.execute("COMMIT;")
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            raise ReceiptError(f"Failed to persist pending approval: {exc}") from exc
        finally:
            conn.close()

        return PendingApprovalRecord(
            crossing_id=envelope.crossing_id,
            session_id=envelope.session_id,
            canonical_hash=envelope.canonical_hash,
            tool=envelope.action.tool,
            verb=envelope.action.verb,
            resource=envelope.action.resource,
            risk_tags=decision.risk_tags,
            reason=decision.reason[:1000],
            params=dict(envelope.action.params),
            ts=envelope.ts,
            expires_at=expires_at,
            status="pending",
            resolution_ts=None,
        )

    def cleanup_expired_approvals(self) -> int:
        """Mark pending or approved approvals whose TTL has expired as 'expired'."""
        now = time.time()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            cur = conn.execute(
                "UPDATE pending_approvals SET status = 'expired', resolution_ts = ? "
                "WHERE status IN ('pending', 'approved') AND expires_at <= ?;",
                (utc_now_iso(), now),
            )
            count = cur.rowcount
            conn.execute("COMMIT;")
            return count
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            raise ReceiptError(f"Failed to cleanup expired approvals: {exc}") from exc
        finally:
            conn.close()

    def recover_pending_approvals(self) -> int:
        """Recover pending approvals state upon service startup."""
        return self.cleanup_expired_approvals()

    def list_pending_approvals(
        self,
        *,
        status: str | None = "pending",
        limit: int = 100,
    ) -> list[PendingApprovalRecord]:
        """List pending approvals matching status, ordered by expiration."""
        self.cleanup_expired_approvals()
        conn = self._connect()
        try:
            if status is not None:
                cur = conn.execute(
                    "SELECT crossing_id, session_id, canonical_hash, tool, verb, "
                    "resource, risk_tags_json, reason, params_json, ts, expires_at, "
                    "status, resolution_ts FROM pending_approvals "
                    "WHERE status = ? ORDER BY expires_at ASC LIMIT ?;",
                    (status, limit),
                )
            else:
                cur = conn.execute(
                    "SELECT crossing_id, session_id, canonical_hash, tool, verb, "
                    "resource, risk_tags_json, reason, params_json, ts, expires_at, "
                    "status, resolution_ts FROM pending_approvals "
                    "ORDER BY ts DESC LIMIT ?;",
                    (limit,),
                )
            rows = cur.fetchall()
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to list pending approvals: {exc}") from exc
        finally:
            conn.close()

        out: list[PendingApprovalRecord] = []
        for r in rows:
            risk_list = json.loads(str(r[6]))
            params_dict = json.loads(str(r[8]))
            out.append(
                PendingApprovalRecord(
                    crossing_id=str(r[0]),
                    session_id=str(r[1]),
                    canonical_hash=str(r[2]),
                    tool=str(r[3]),
                    verb=str(r[4]),
                    resource=str(r[5]),
                    risk_tags=tuple(str(t) for t in risk_list),
                    reason=str(r[7]),
                    params=params_dict,
                    ts=str(r[9]),
                    expires_at=float(r[10]),
                    status=str(r[11]),  # type: ignore[arg-type]
                    resolution_ts=str(r[12]) if r[12] is not None else None,
                )
            )
        return out

    def get_pending_approval(self, crossing_id: str) -> PendingApprovalRecord | None:
        """Fetch pending approval record by crossing_id."""
        self.cleanup_expired_approvals()
        conn = self._connect()
        try:
            cur = conn.execute(
                "SELECT crossing_id, session_id, canonical_hash, tool, verb, "
                "resource, risk_tags_json, reason, params_json, ts, expires_at, "
                "status, resolution_ts FROM pending_approvals "
                "WHERE crossing_id = ?;",
                (crossing_id,),
            )
            r = cur.fetchone()
            if r is None:
                return None
            risk_list = json.loads(str(r[6]))
            params_dict = json.loads(str(r[8]))
            return PendingApprovalRecord(
                crossing_id=str(r[0]),
                session_id=str(r[1]),
                canonical_hash=str(r[2]),
                tool=str(r[3]),
                verb=str(r[4]),
                resource=str(r[5]),
                risk_tags=tuple(str(t) for t in risk_list),
                reason=str(r[7]),
                params=params_dict,
                ts=str(r[9]),
                expires_at=float(r[10]),
                status=str(r[11]),  # type: ignore[arg-type]
                resolution_ts=str(r[12]) if r[12] is not None else None,
            )
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to get pending approval: {exc}") from exc
        finally:
            conn.close()

    def resolve_pending_approval(
        self, crossing_id: str, *, approved: bool
    ) -> PendingApprovalRecord | None:
        """Resolve a pending approval to approved or rejected (single-use)."""
        self.cleanup_expired_approvals()
        new_status = "approved" if approved else "rejected"
        now_iso = utc_now_iso()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            cur = conn.execute(
                "UPDATE pending_approvals SET status = ?, resolution_ts = ? "
                "WHERE crossing_id = ? AND status = 'pending';",
                (new_status, now_iso, crossing_id),
            )
            if cur.rowcount == 0:
                conn.execute("ROLLBACK;")
                return None
            conn.execute("COMMIT;")
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            raise ReceiptError(f"Failed to resolve pending approval: {exc}") from exc
        finally:
            conn.close()

        return self.get_pending_approval(crossing_id)

    def mark_approval_consumed(self, crossing_id: str) -> bool:
        """Mark an approved crossing as consumed after execution."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            cur = conn.execute(
                "UPDATE pending_approvals SET status = 'consumed' "
                "WHERE crossing_id = ? AND status = 'approved';",
                (crossing_id,),
            )
            updated = cur.rowcount > 0
            conn.execute("COMMIT;")
            return updated
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            raise ReceiptError(f"Failed to mark approval consumed: {exc}") from exc
        finally:
            conn.close()

    def claim_approval_for_execution(self, crossing_id: str) -> bool:
        """Atomically transition an approved crossing to 'consumed' before execution dispatch.

        Returns True if the approval was valid ('approved' and unexpired) and successfully claimed.
        Returns False if already consumed, expired, rejected, or missing.
        """
        self.cleanup_expired_approvals()
        now = time.time()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            cur = conn.execute(
                "UPDATE pending_approvals SET status = 'consumed' "
                "WHERE crossing_id = ? AND status = 'approved' AND expires_at > ?;",
                (crossing_id, now),
            )
            claimed = cur.rowcount > 0
            conn.execute("COMMIT;")
            return claimed
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            raise ReceiptError(f"Failed to claim approval for execution: {exc}") from exc
        finally:
            conn.close()

    def query_records(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        verdict: str | None = None,
        tool: str | None = None,
        status: str | None = None,
        session_id: str | None = None,
        record_type: str | None = None,
        search: str | None = None,
    ) -> tuple[list[ReceiptRecord], int]:
        """Query bounded receipts with optional filters and total count."""
        limit = max(1, min(limit, 500))
        offset = max(0, offset)
        where_clauses: list[str] = []
        params: list[Any] = []

        if record_type:
            where_clauses.append("r.record_type = ?")
            params.append(record_type)
        if verdict:
            where_clauses.append("r.verdict = ?")
            params.append(verdict)
        if status:
            where_clauses.append("r.status = ?")
            params.append(status)
        if session_id:
            where_clauses.append("r.session_id = ?")
            params.append(session_id)
        if tool:
            where_clauses.append("json_extract(a.envelope_json, '$.action.tool') = ?")
            params.append(tool)
        if search:
            where_clauses.append(
                "(r.crossing_id LIKE ? OR r.reason LIKE ? OR r.rule_id LIKE ? OR "
                "json_extract(a.envelope_json, '$.action.tool') LIKE ? OR "
                "json_extract(a.envelope_json, '$.action.resource') LIKE ?)"
            )
            term = f"%{search}%"
            params.extend([term, term, term, term, term])

        where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        from_sql = " FROM receipts r LEFT JOIN action_envelopes a ON r.crossing_id = a.crossing_id"

        count_sql = f"SELECT COUNT(*) {from_sql}{where_sql};"
        select_sql = (
            f"SELECT r.seq, r.record_type, r.crossing_id, r.session_id, r.canonical_hash, "
            f"r.policy_version, r.verdict, r.rule_id, r.reason, r.risk_tags_json, "
            f"r.shadow, r.status, r.result_hash, r.error, r.ts, r.prev_hash, r.entry_hash "
            f"{from_sql}{where_sql} ORDER BY r.seq DESC LIMIT ? OFFSET ?;"
        )

        conn = self._connect()
        try:
            total_count = int(conn.execute(count_sql, params).fetchone()[0])
            select_params = list(params) + [limit, offset]
            rows = conn.execute(select_sql, select_params).fetchall()
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to query receipts: {exc}") from exc
        finally:
            conn.close()

        records: list[ReceiptRecord] = []
        for row in rows:
            risk_list = json.loads(str(row[9]))
            rec_type: Literal["decision", "outcome"] = (
                "decision" if row[1] == "decision" else "outcome"
            )
            records.append(
                ReceiptRecord(
                    seq=int(row[0]),
                    record_type=rec_type,
                    crossing_id=str(row[2]),
                    session_id=str(row[3]),
                    canonical_hash=str(row[4]),
                    policy_version=str(row[5]),
                    verdict=str(row[6]) if row[6] is not None else None,
                    rule_id=str(row[7]) if row[7] is not None else None,
                    reason=str(row[8]) if row[8] is not None else None,
                    risk_tags=tuple(str(t) for t in risk_list),
                    shadow=bool(row[10]),
                    status=str(row[11]) if row[11] is not None else None,
                    result_hash=str(row[12]) if row[12] is not None else None,
                    error=str(row[13]) if row[13] is not None else None,
                    ts=str(row[14]),
                    prev_hash=str(row[15]),
                    entry_hash=str(row[16]),
                )
            )
        return records, total_count


def verify_log(
    db_path: str | Path,
    *,
    verify_envelopes: bool = False,
    chunk_size: int = 500,
) -> VerificationResult:
    """Verify hash-chain integrity, sequence continuity, and digests in bounded streaming memory.

    If verify_envelopes is True, additionally verifies that stored action envelopes
    exist for each decision receipt and their recomputed action hash matches the decision.
    """
    path = Path(db_path)
    if not path.exists():
        return VerificationResult(
            ok=False,
            total_records=0,
            last_hash=GENESIS_HASH,
            errors=(f"Receipt database not found: {path}",),
        )

    errors: list[str] = []
    expected_prev = GENESIS_HASH
    expected_seq = 1
    last_hash = GENESIS_HASH
    total_records = 0

    try:
        store = ReceiptStore(path)
    except Exception as exc:
        return VerificationResult(
            ok=False,
            total_records=0,
            last_hash=GENESIS_HASH,
            errors=(f"Unable to read receipt database: {exc}",),
        )

    conn: sqlite3.Connection | None = None
    if verify_envelopes:
        try:
            conn = store._connect()
        except sqlite3.Error:
            conn = None

    try:
        for rec in store.iter_records_stream(chunk_size=chunk_size):
            total_records += 1
            if rec.seq != expected_seq:
                errors.append(f"seq {rec.seq}: expected sequence number {expected_seq}")
            if rec.prev_hash != expected_prev:
                errors.append(
                    f"seq {rec.seq}: prev_hash mismatch "
                    f"(expected {expected_prev}, got {rec.prev_hash})"
                )
            computed = _compute_entry_hash(
                seq=rec.seq,
                record_type=rec.record_type,
                crossing_id=rec.crossing_id,
                session_id=rec.session_id,
                canonical_hash=rec.canonical_hash,
                policy_version=rec.policy_version,
                verdict=rec.verdict,
                rule_id=rec.rule_id,
                reason=rec.reason,
                risk_tags=rec.risk_tags,
                shadow=rec.shadow,
                status=rec.status,
                result_hash=rec.result_hash,
                error=rec.error,
                ts=rec.ts,
                prev_hash=rec.prev_hash,
            )
            if computed != rec.entry_hash:
                errors.append(
                    f"seq {rec.seq}: entry_hash mismatch "
                    f"(computed {computed}, stored {rec.entry_hash})"
                )

            if verify_envelopes and rec.record_type == "decision" and conn is not None:
                cur = conn.execute(
                    "SELECT envelope_json FROM action_envelopes WHERE crossing_id = ?;",
                    (rec.crossing_id,),
                )
                env_row = cur.fetchone()
                if env_row is None or not env_row[0]:
                    errors.append(
                        f"seq {rec.seq} (crossing {rec.crossing_id}): "
                        "missing stored action envelope"
                    )
                else:
                    try:
                        env_data = json.loads(env_row[0])
                        action_data = env_data.get("action") or {}
                        agent_data = env_data.get("agent") or {}
                        act_spec = ActionSpec(
                            tool=str(action_data.get("tool", "")),
                            verb=str(action_data.get("verb", "other")),
                            resource=str(action_data.get("resource", "")),
                            params=action_data.get("params") or {},
                            idempotency_key=action_data.get("idempotency_key"),
                        )
                        computed_act_hash = compute_action_hash(
                            envelope_version=str(env_data.get("envelope_version", "1")),
                            session_id=str(env_data.get("session_id", "")),
                            agent_id=str(agent_data.get("id", "")),
                            action=act_spec,
                        )
                        if computed_act_hash != rec.canonical_hash:
                            errors.append(
                                f"seq {rec.seq} (crossing {rec.crossing_id}): "
                                "envelope action hash mismatch "
                                f"(computed {computed_act_hash}, receipt {rec.canonical_hash})"
                            )
                    except Exception as exc:
                        errors.append(
                            f"seq {rec.seq} (crossing {rec.crossing_id}): "
                            f"envelope verification error: {exc}"
                        )

            expected_prev = rec.entry_hash
            last_hash = rec.entry_hash
            expected_seq += 1
    except (ReceiptError, sqlite3.Error, json.JSONDecodeError) as exc:
        errors.append(f"Unable to read receipt database: {exc}")
    finally:
        if conn is not None:
            conn.close()

    return VerificationResult(
        ok=len(errors) == 0,
        total_records=total_records,
        last_hash=last_hash,
        errors=tuple(errors),
    )


def export_jsonl(
    db_path: str | Path,
    out_path: str | Path,
    *,
    chunk_size: int = 500,
) -> int:
    """Export all receipt records to a JSONL file in bounded streaming chunks."""
    store = ReceiptStore(db_path)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        for rec in store.iter_records_stream(chunk_size=chunk_size):
            fh.write(json.dumps(rec.to_dict(), ensure_ascii=False) + "\n")
            count += 1
    return count
