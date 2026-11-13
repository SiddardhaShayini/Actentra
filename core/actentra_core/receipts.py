"""Tamper-evident, hash-chained SQLite receipt log for Actentra."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from actentra_core.canonicalize import canonicalize_json, hash_canonical
from actentra_core.envelope import ActionEnvelope, utc_now_iso
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
                CREATE TABLE IF NOT EXISTS action_envelopes (
                    crossing_id TEXT PRIMARY KEY,
                    envelope_json TEXT NOT NULL
                );
                """
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
    ) -> ReceiptRecord:
        stamp = ts or utc_now_iso()
        risk_json = canonicalize_json(list(risk_tags))
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
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
            conn.execute("COMMIT;")
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            raise ReceiptError(f"Failed to commit receipt record: {exc}") from exc
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
        """Persist an immutable decision record before any execution occurs (I5)."""
        rec = self._append_record(
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
        )
        conn = self._connect()
        try:
            sql_insert = (
                "INSERT OR REPLACE INTO action_envelopes "
                "(crossing_id, envelope_json) VALUES (?, ?);"
            )
            conn.execute(
                sql_insert,
                (envelope.crossing_id, canonicalize_json(envelope.to_dict())),
            )
            conn.execute("COMMIT;")
        except sqlite3.Error:
            pass
        finally:
            conn.close()
        return rec

    def get_envelope(self, crossing_id: str) -> dict[str, Any] | None:
        """Retrieve stored envelope payload for a crossing if available."""
        conn = self._connect()
        try:
            cur = conn.execute(
                "SELECT envelope_json FROM action_envelopes WHERE crossing_id = ?;",
                (crossing_id,),
            )
            row = cur.fetchone()
            if row and row[0]:
                data = json.loads(row[0])
                return data if isinstance(data, dict) else None
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
    ) -> ReceiptRecord:
        """Append an immutable post-execution outcome record (success, failure, or unknown)."""
        if status not in _VALID_OUTCOMES:
            raise ReceiptError(f"Invalid outcome status: {status!r}")
        safe_error = error[:1000] if error is not None else None
        return self._append_record(
            record_type="outcome",
            crossing_id=crossing_id,
            session_id=session_id,
            canonical_hash=canonical_hash,
            policy_version=policy_version,
            verdict=None,
            rule_id=None,
            reason=None,
            risk_tags=(),
            shadow=False,
            status=status,
            result_hash=result_hash,
            error=safe_error,
        )

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

    def iter_records(self) -> list[ReceiptRecord]:
        """Return all stored receipt records in sequence order."""
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT seq, record_type, crossing_id, session_id, canonical_hash,
                       policy_version, verdict, rule_id, reason, risk_tags_json,
                       shadow, status, result_hash, error, ts, prev_hash, entry_hash
                FROM receipts
                ORDER BY seq ASC;
                """
            ).fetchall()
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to read receipt records: {exc}") from exc
        finally:
            conn.close()

        out: list[ReceiptRecord] = []
        for row in rows:
            risk_list = json.loads(str(row[9]))
            rec_type: Literal["decision", "outcome"] = (
                "decision" if row[1] == "decision" else "outcome"
            )
            out.append(
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
        return out


def verify_log(db_path: str | Path) -> VerificationResult:
    """Verify hash-chain integrity, sequence continuity, and record digests."""
    path = Path(db_path)
    if not path.exists():
        return VerificationResult(
            ok=False,
            total_records=0,
            last_hash=GENESIS_HASH,
            errors=(f"Receipt database not found: {path}",),
        )

    try:
        store = ReceiptStore(path)
        records = store.iter_records()
    except (ReceiptError, sqlite3.Error, json.JSONDecodeError) as exc:
        return VerificationResult(
            ok=False,
            total_records=0,
            last_hash=GENESIS_HASH,
            errors=(f"Unable to read receipt database: {exc}",),
        )

    errors: list[str] = []
    expected_prev = GENESIS_HASH
    expected_seq = 1
    last_hash = GENESIS_HASH

    for rec in records:
        if rec.seq != expected_seq:
            errors.append(f"seq {rec.seq}: expected sequence number {expected_seq}")
        if rec.prev_hash != expected_prev:
            errors.append(
                f"seq {rec.seq}: prev_hash mismatch (expected {expected_prev}, got {rec.prev_hash})"
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
                f"seq {rec.seq}: entry_hash mismatch (computed {computed}, stored {rec.entry_hash})"
            )
        expected_prev = rec.entry_hash
        last_hash = rec.entry_hash
        expected_seq += 1

    return VerificationResult(
        ok=len(errors) == 0,
        total_records=len(records),
        last_hash=last_hash,
        errors=tuple(errors),
    )


def export_jsonl(db_path: str | Path, out_path: str | Path) -> int:
    """Export all receipt records to a JSONL file. Returns record count."""
    store = ReceiptStore(db_path)
    records = store.iter_records()
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        for rec in records:
            fh.write(json.dumps(rec.to_dict(), ensure_ascii=False) + "\n")
    return len(records)
