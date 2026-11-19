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
from actentra_core.causal import (
    CausalLink,
    CausalTraceEdge,
    CycleDetectedError,
    detect_cycles,
)
from actentra_core.coordination import (
    ResourceConflictError,
    ResourceLease,
)
from actentra_core.coordination import (
    utc_iso as utc_lease_iso,
)
from actentra_core.envelope import (
    ActionEnvelope,
    ActionSpec,
    compute_action_hash,
    utc_now_iso,
)
from actentra_core.evidence import EvidenceRecord, EvidenceTier
from actentra_core.handoffs import TaskHandoffRecord
from actentra_core.observations import ObservationRecord
from actentra_core.verdict import Decision

GENESIS_HASH = "sha256:" + ("0" * 64)
OutcomeStatus = Literal["success", "failure", "unknown"]
_VALID_OUTCOMES = frozenset({"success", "failure", "unknown"})
EvidenceStatus = Literal[
    "locally_observed", "caller_reported", "externally_verified", "stale", "unknown"
]
_VALID_EVIDENCE_STATUSES = frozenset(
    {"locally_observed", "caller_reported", "externally_verified", "stale", "unknown"}
)


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
    evidence_status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
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
        if self.evidence_status is not None:
            d["evidence_status"] = self.evidence_status
        return d


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


def _row_to_receipt_record(row: tuple[Any, ...]) -> ReceiptRecord:
    risk_list = json.loads(str(row[9]))
    rec_type: Literal["decision", "outcome"] = "decision" if row[1] == "decision" else "outcome"
    evidence_status = str(row[17]) if len(row) > 17 and row[17] is not None else None
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
        evidence_status=evidence_status,
    )


class ReceiptStore:
    """Append-only SQLite WAL receipt store with SHA-256 hash chaining."""

    def __init__(self, db_path: str | Path, *, synchronous: str = "NORMAL") -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._synchronous = synchronous if synchronous in ("FULL", "NORMAL", "EXTRA") else "NORMAL"
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
                    entry_hash TEXT NOT NULL,
                    evidence_status TEXT CHECK (
                        evidence_status IN (
                            'locally_observed', 'caller_reported', 'externally_verified',
                            'stale', 'unknown'
                        ) OR evidence_status IS NULL
                    )
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS observations (
                    observation_id TEXT PRIMARY KEY,
                    crossing_id TEXT,
                    subject_resource TEXT NOT NULL,
                    claim TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('verified', 'refuted', 'unknown', 'error', 'stale')
                    ),
                    observed_digest TEXT,
                    observed_at TEXT NOT NULL,
                    expires_at TEXT,
                    verifier_id TEXT NOT NULL,
                    verifier_version TEXT NOT NULL,
                    trust_domain TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    error TEXT,
                    observation_hash TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_obs_crossing ON observations(crossing_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_obs_resource ON observations(subject_resource);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_obs_observed_at ON observations(observed_at);"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS causal_links (
                    link_id TEXT PRIMARY KEY,
                    link_version TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_causal_links_source
                ON causal_links(source_type, source_id);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_causal_links_target
                ON causal_links(target_type, target_id);
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS task_handoffs (
                    handoff_id TEXT PRIMARY KEY,
                    handoff_version TEXT NOT NULL DEFAULT '1',
                    task_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('active', 'completed', 'revoked', 'expired', 'contradicted')
                    ),
                    current_step INTEGER NOT NULL DEFAULT 1,
                    initiator_agent_id TEXT NOT NULL,
                    assigned_agent_id TEXT NOT NULL,
                    verifier_agent_id TEXT NOT NULL,
                    allowed_verbs_json TEXT NOT NULL DEFAULT '[]',
                    allowed_resources_json TEXT NOT NULL DEFAULT '[]',
                    prior_crossings_json TEXT NOT NULL DEFAULT '[]',
                    prior_observations_json TEXT NOT NULL DEFAULT '[]',
                    assertions_json TEXT NOT NULL DEFAULT '{}',
                    contradictions_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    handoff_hash TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_handoff_task ON task_handoffs(task_id);")
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_handoff_assigned
                ON task_handoffs(assigned_agent_id);
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_handoff_status ON task_handoffs(status);")

            # Migration for evidence_status on existing receipts tables
            with contextlib.suppress(sqlite3.OperationalError):
                conn.execute(
                    "ALTER TABLE receipts ADD COLUMN evidence_status TEXT CHECK ("
                    "evidence_status IN ("
                    "'locally_observed', 'caller_reported', 'externally_verified', "
                    "'stale', 'unknown') OR evidence_status IS NULL"
                    ");"
                )

            # Phase 5: Typed evidence records table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_records (
                    evidence_id TEXT PRIMARY KEY,
                    crossing_id TEXT NOT NULL,
                    tier TEXT NOT NULL CHECK (
                        tier IN (
                            'locally_observed', 'caller_reported', 'externally_verified',
                            'stale', 'unknown'
                        )
                    ),
                    trust_domain TEXT NOT NULL,
                    collector TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    expires_at TEXT,
                    details_json TEXT NOT NULL,
                    evidence_hash TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_evidence_crossing ON evidence_records(crossing_id);"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_tier ON evidence_records(tier);")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_evidence_observed ON evidence_records(observed_at);"
            )

            # Phase 5: Persistent session cumulative budgets across restarts
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_budgets (
                    session_id TEXT PRIMARY KEY,
                    actions_count INTEGER NOT NULL DEFAULT 0,
                    external_calls_count INTEGER NOT NULL DEFAULT 0,
                    write_bytes_count INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                """
            )

            # Phase 5: Persistent session taints across restarts
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_taints (
                    session_id TEXT PRIMARY KEY,
                    taint_level TEXT NOT NULL CHECK (
                        taint_level IN ('trusted', 'untrusted', 'unknown')
                    ),
                    updated_at TEXT NOT NULL
                );
                """
            )

            # Phase 6: Durable resource leases for multi-agent coordination
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS resource_leases (
                    lease_id TEXT PRIMARY KEY,
                    lease_version TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    owner_agent_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    mode TEXT NOT NULL CHECK (mode IN ('exclusive', 'shared')),
                    status TEXT NOT NULL CHECK (status IN ('active', 'released', 'expired')),
                    acquired_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    lease_hash TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_lease_resource ON resource_leases(resource);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_lease_owner ON resource_leases("
                "owner_agent_id, status);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_lease_status_exp ON resource_leases("
                "status, expires_at);"
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
        evidence_status: str | None = None,
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
                    shadow, status, result_hash, error, ts, prev_hash, entry_hash,
                    evidence_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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
                    evidence_status,
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
            evidence_status=evidence_status,
        )

    def record_decision(self, envelope: ActionEnvelope, decision: Decision) -> ReceiptRecord:
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
        evidence_status: str | None = None,
    ) -> ReceiptRecord:
        """Append an immutable post-execution outcome record (success, failure, or unknown)."""
        if status not in _VALID_OUTCOMES:
            raise ReceiptError(f"Invalid outcome status: {status!r}")
        safe_error = error[:1000] if error is not None else None
        safe_reason = reason[:1000] if reason is not None else None

        # Derive evidence_status if not explicitly supplied
        ev_status = evidence_status
        if ev_status is None:
            if status == "unknown":
                ev_status = "unknown"
            elif safe_reason == "caller-reported":
                ev_status = "caller_reported"
            else:
                ev_status = "locally_observed"
        elif ev_status not in _VALID_EVIDENCE_STATUSES:
            valid_statuses = sorted(_VALID_EVIDENCE_STATUSES)
            raise ReceiptError(
                f"Invalid evidence status: {ev_status!r}; expected one of {valid_statuses}"
            )

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
            evidence_status=ev_status,
        )

    def get_decision_receipt(self, crossing_id: str) -> ReceiptRecord | None:
        """Fetch the decision receipt record for a crossing_id if one exists."""
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT seq, record_type, crossing_id, session_id, canonical_hash,
                       policy_version, verdict, rule_id, reason, risk_tags_json,
                       shadow, status, result_hash, error, ts, prev_hash, entry_hash,
                       evidence_status
                FROM receipts
                WHERE crossing_id = ? AND record_type = 'decision'
                ORDER BY seq DESC LIMIT 1;
                """,
                (crossing_id,),
            ).fetchone()
            if row is None:
                return None
            return _row_to_receipt_record(row)
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to fetch decision receipt: {exc}") from exc
        finally:
            conn.close()

    def get_outcome_receipt(self, crossing_id: str) -> ReceiptRecord | None:
        """Fetch the outcome receipt record for a crossing_id if one exists."""
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT seq, record_type, crossing_id, session_id, canonical_hash,
                       policy_version, verdict, rule_id, reason, risk_tags_json,
                       shadow, status, result_hash, error, ts, prev_hash, entry_hash,
                       evidence_status
                FROM receipts
                WHERE crossing_id = ? AND record_type = 'outcome'
                ORDER BY seq DESC LIMIT 1;
                """,
                (crossing_id,),
            ).fetchone()
            if row is None:
                return None
            return _row_to_receipt_record(row)
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to fetch outcome receipt: {exc}") from exc
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
                           shadow, status, result_hash, error, ts, prev_hash, entry_hash,
                           evidence_status
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
                           shadow, status, result_hash, error, ts, prev_hash, entry_hash,
                           evidence_status
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
                    yield _row_to_receipt_record(row)
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
                       shadow, status, result_hash, error, ts, prev_hash, entry_hash,
                       evidence_status
                FROM receipts
                ORDER BY seq DESC LIMIT 1;
                """
            ).fetchone()
            if row is None:
                return None
            return _row_to_receipt_record(row)
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
            f"r.shadow, r.status, r.result_hash, r.error, r.ts, r.prev_hash, r.entry_hash, "
            f"r.evidence_status "
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

        records = [_row_to_receipt_record(row) for row in rows]
        return records, total_count

    # --- 8. State Observations (Phase 2) ---

    def record_observation(self, obs: ObservationRecord) -> ObservationRecord:
        """Persist a verifiable state observation record."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute(
                """
                INSERT OR REPLACE INTO observations (
                    observation_id, crossing_id, subject_resource, claim, status,
                    observed_digest, observed_at, expires_at, verifier_id,
                    verifier_version, trust_domain, metadata_json, error, observation_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    obs.observation_id,
                    obs.crossing_id,
                    obs.subject_resource,
                    obs.claim,
                    obs.status,
                    obs.observed_digest,
                    obs.observed_at,
                    obs.expires_at,
                    obs.verifier_id,
                    obs.verifier_version,
                    obs.trust_domain,
                    json.dumps(obs.metadata, ensure_ascii=False),
                    obs.error,
                    obs.observation_hash,
                ),
            )
            conn.execute("COMMIT;")
            return obs
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            raise ReceiptError(f"Failed to record observation: {exc}") from exc
        finally:
            conn.close()

    def get_observation(self, observation_id: str) -> ObservationRecord | None:
        """Fetch a specific observation by ID."""
        conn = self._connect()
        try:
            cur = conn.execute(
                """
                SELECT observation_id, crossing_id, subject_resource, claim, status,
                       observed_digest, observed_at, expires_at, verifier_id,
                       verifier_version, trust_domain, metadata_json, error, observation_hash
                FROM observations WHERE observation_id = ?;
                """,
                (observation_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return self._row_to_observation(row)
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to fetch observation: {exc}") from exc
        finally:
            conn.close()

    def get_latest_observation(
        self,
        subject_resource: str,
        claim: str | None = None,
    ) -> ObservationRecord | None:
        """Fetch the most recent observation for a subject resource and optional claim."""
        conn = self._connect()
        try:
            if claim is not None:
                cur = conn.execute(
                    """
                    SELECT observation_id, crossing_id, subject_resource, claim, status,
                           observed_digest, observed_at, expires_at, verifier_id,
                           verifier_version, trust_domain, metadata_json, error, observation_hash
                    FROM observations
                    WHERE subject_resource = ? AND claim = ?
                    ORDER BY observed_at DESC, rowid DESC LIMIT 1;
                    """,
                    (subject_resource, claim),
                )
            else:
                cur = conn.execute(
                    """
                    SELECT observation_id, crossing_id, subject_resource, claim, status,
                           observed_digest, observed_at, expires_at, verifier_id,
                           verifier_version, trust_domain, metadata_json, error, observation_hash
                    FROM observations
                    WHERE subject_resource = ?
                    ORDER BY observed_at DESC, rowid DESC LIMIT 1;
                    """,
                    (subject_resource,),
                )
            row = cur.fetchone()
            if row is None:
                return None
            return self._row_to_observation(row)
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to fetch latest observation: {exc}") from exc
        finally:
            conn.close()

    def list_observations(
        self,
        *,
        crossing_id: str | None = None,
        subject_resource: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ObservationRecord]:
        """List observations with optional filtering and pagination."""
        clamped_limit = max(1, min(limit, 500))
        clamped_offset = max(0, offset)
        conn = self._connect()
        try:
            query = (
                "SELECT observation_id, crossing_id, subject_resource, claim, status, "
                "observed_digest, observed_at, expires_at, verifier_id, "
                "verifier_version, trust_domain, metadata_json, error, observation_hash "
                "FROM observations "
            )
            params: list[Any] = []
            clauses: list[str] = []
            if crossing_id is not None:
                clauses.append("crossing_id = ?")
                params.append(crossing_id)
            if subject_resource is not None:
                clauses.append("subject_resource = ?")
                params.append(subject_resource)
            if clauses:
                query += " WHERE " + " AND ".join(clauses)
            query += " ORDER BY observed_at DESC, rowid DESC LIMIT ? OFFSET ?;"
            params.extend([clamped_limit, clamped_offset])

            cur = conn.execute(query, tuple(params))
            rows = cur.fetchall()
            return [self._row_to_observation(r) for r in rows]
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to list observations: {exc}") from exc
        finally:
            conn.close()

    def count_observations(self, *, subject_resource: str | None = None) -> int:
        """Count total observations, optionally filtered by resource."""
        conn = self._connect()
        try:
            if subject_resource is not None:
                cur = conn.execute(
                    "SELECT COUNT(*) FROM observations WHERE subject_resource = ?;",
                    (subject_resource,),
                )
            else:
                cur = conn.execute("SELECT COUNT(*) FROM observations;")
            row = cur.fetchone()
            return int(row[0]) if row else 0
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to count observations: {exc}") from exc
        finally:
            conn.close()

    @staticmethod
    def _row_to_observation(row: tuple[Any, ...]) -> ObservationRecord:
        meta_raw = row[11]
        try:
            meta = json.loads(meta_raw) if isinstance(meta_raw, str) else dict(meta_raw)
        except Exception:
            meta = {}
        return ObservationRecord(
            observation_id=str(row[0]),
            observation_version="1",
            crossing_id=str(row[1]) if row[1] is not None else None,
            subject_resource=str(row[2]),
            claim=str(row[3]),
            status=row[4],
            observed_digest=str(row[5]) if row[5] is not None else None,
            observed_at=str(row[6]),
            expires_at=str(row[7]) if row[7] is not None else None,
            verifier_id=str(row[8]),
            verifier_version=str(row[9]),
            trust_domain=row[10],
            metadata=meta,
            error=str(row[12]) if row[12] is not None else None,
            observation_hash=str(row[13]),
        )

    # --- 9. Causal Links and Trace (Phase 3) ---

    def record_causal_link(self, link: CausalLink) -> CausalLink:
        """Persist a typed causal link, validating that it does not introduce cycles."""
        existing_links = self.list_causal_links(limit=1000)
        edges: list[CausalTraceEdge] = []
        for el in existing_links:
            if el.relation in ("caused_by", "verifies", "derived_from", "part_of"):
                src, tgt = el.target_id, el.source_id
            else:
                src, tgt = el.source_id, el.target_id
            edges.append(
                CausalTraceEdge(
                    source_id=src,
                    target_id=tgt,
                    relation=el.relation,
                    edge_type="explicit",
                )
            )

        if link.relation in ("caused_by", "verifies", "derived_from", "part_of"):
            cand_src, cand_tgt = link.target_id, link.source_id
        else:
            cand_src, cand_tgt = link.source_id, link.target_id
        edges.append(
            CausalTraceEdge(
                source_id=cand_src,
                target_id=cand_tgt,
                relation=link.relation,
                edge_type="explicit",
            )
        )

        if detect_cycles(edges):
            raise CycleDetectedError(
                f"Causal link introduces a cycle between '{link.source_id}' and '{link.target_id}'"
            )

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute(
                """
                INSERT OR REPLACE INTO causal_links (
                    link_id, link_version, source_id, source_type, relation,
                    target_id, target_type, created_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    link.link_id,
                    link.link_version,
                    link.source_id,
                    link.source_type,
                    link.relation,
                    link.target_id,
                    link.target_type,
                    link.created_at,
                    json.dumps(link.metadata, ensure_ascii=False),
                ),
            )
            conn.execute("COMMIT;")
            return link
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            raise ReceiptError(f"Failed to record causal link: {exc}") from exc
        finally:
            conn.close()

    def get_causal_link(self, link_id: str) -> CausalLink | None:
        """Fetch a causal link by ID."""
        conn = self._connect()
        try:
            cur = conn.execute(
                """
                SELECT link_id, link_version, source_id, source_type, relation,
                       target_id, target_type, created_at, metadata_json
                FROM causal_links WHERE link_id = ?;
                """,
                (link_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return self._row_to_causal_link(row)
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to fetch causal link: {exc}") from exc
        finally:
            conn.close()

    def list_causal_links(
        self,
        entity_id: str | None = None,
        *,
        limit: int = 100,
    ) -> list[CausalLink]:
        """List causal links, optionally filtered by source or target entity ID."""
        conn = self._connect()
        try:
            if entity_id is not None:
                cur = conn.execute(
                    """
                    SELECT link_id, link_version, source_id, source_type, relation,
                           target_id, target_type, created_at, metadata_json
                    FROM causal_links
                    WHERE source_id = ? OR target_id = ?
                    ORDER BY created_at ASC, rowid ASC LIMIT ?;
                    """,
                    (entity_id, entity_id, limit),
                )
            else:
                cur = conn.execute(
                    """
                    SELECT link_id, link_version, source_id, source_type, relation,
                           target_id, target_type, created_at, metadata_json
                    FROM causal_links
                    ORDER BY created_at ASC, rowid ASC LIMIT ?;
                    """,
                    (limit,),
                )
            rows = cur.fetchall()
            return [self._row_to_causal_link(row) for row in rows]
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to list causal links: {exc}") from exc
        finally:
            conn.close()

    def delete_causal_link(self, link_id: str) -> bool:
        """Delete a causal link by ID. Returns True if deleted, False if not found."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            cur = conn.execute("DELETE FROM causal_links WHERE link_id = ?;", (link_id,))
            deleted = cur.rowcount > 0
            conn.execute("COMMIT;")
            return deleted
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            raise ReceiptError(f"Failed to delete causal link: {exc}") from exc
        finally:
            conn.close()

    def count_causal_links(self) -> int:
        """Return total number of causal links stored."""
        conn = self._connect()
        try:
            cur = conn.execute("SELECT COUNT(*) FROM causal_links;")
            row = cur.fetchone()
            return int(row[0]) if row else 0
        finally:
            conn.close()

    @staticmethod
    def _row_to_causal_link(row: tuple[Any, ...]) -> CausalLink:
        try:
            meta = json.loads(str(row[8])) if row[8] else {}
        except Exception:
            meta = {}
        return CausalLink(
            link_id=str(row[0]),
            link_version=str(row[1]),
            source_id=str(row[2]),
            source_type=row[3],
            relation=row[4],
            target_id=str(row[5]),
            target_type=row[6],
            created_at=str(row[7]),
            metadata=meta,
        )

    # --- 10. Task Handoffs and Cross-Agent Continuity (Phase 4) ---

    def record_handoff(self, handoff: TaskHandoffRecord) -> TaskHandoffRecord:
        """Persist a task handoff record."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute(
                """
                INSERT OR REPLACE INTO task_handoffs (
                    handoff_id, handoff_version, task_id, status, current_step,
                    initiator_agent_id, assigned_agent_id, verifier_agent_id,
                    allowed_verbs_json, allowed_resources_json, prior_crossings_json,
                    prior_observations_json, assertions_json, contradictions_json,
                    created_at, expires_at, handoff_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    handoff.handoff_id,
                    handoff.handoff_version,
                    handoff.task_id,
                    handoff.status,
                    handoff.current_step,
                    handoff.initiator_agent_id,
                    handoff.assigned_agent_id,
                    handoff.verifier_agent_id,
                    json.dumps(list(handoff.allowed_verbs), ensure_ascii=False),
                    json.dumps(list(handoff.allowed_resources), ensure_ascii=False),
                    json.dumps(list(handoff.prior_crossings), ensure_ascii=False),
                    json.dumps(list(handoff.prior_observations), ensure_ascii=False),
                    json.dumps(handoff.assertions, ensure_ascii=False),
                    json.dumps(list(handoff.contradictions), ensure_ascii=False),
                    handoff.created_at,
                    handoff.expires_at,
                    handoff.handoff_hash,
                ),
            )
            conn.execute("COMMIT;")
            return handoff
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            raise ReceiptError(f"Failed to record handoff: {exc}") from exc
        finally:
            conn.close()

    def get_handoff(self, handoff_id: str) -> TaskHandoffRecord | None:
        """Fetch a specific handoff by ID."""
        conn = self._connect()
        try:
            cur = conn.execute(
                """
                SELECT handoff_id, handoff_version, task_id, status, current_step,
                       initiator_agent_id, assigned_agent_id, verifier_agent_id,
                       allowed_verbs_json, allowed_resources_json, prior_crossings_json,
                       prior_observations_json, assertions_json, contradictions_json,
                       created_at, expires_at, handoff_hash
                FROM task_handoffs WHERE handoff_id = ?;
                """,
                (handoff_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return self._row_to_handoff(row)
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to fetch handoff: {exc}") from exc
        finally:
            conn.close()

    def get_active_handoff_by_task(self, task_id: str) -> TaskHandoffRecord | None:
        """Fetch the active handoff for a task."""
        conn = self._connect()
        try:
            cur = conn.execute(
                """
                SELECT handoff_id, handoff_version, task_id, status, current_step,
                       initiator_agent_id, assigned_agent_id, verifier_agent_id,
                       allowed_verbs_json, allowed_resources_json, prior_crossings_json,
                       prior_observations_json, assertions_json, contradictions_json,
                       created_at, expires_at, handoff_hash
                FROM task_handoffs
                WHERE task_id = ? AND status = 'active'
                ORDER BY current_step DESC, rowid DESC LIMIT 1;
                """,
                (task_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return self._row_to_handoff(row)
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to fetch active handoff: {exc}") from exc
        finally:
            conn.close()

    def list_handoffs(
        self,
        *,
        task_id: str | None = None,
        assigned_agent_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[TaskHandoffRecord]:
        """List task handoffs matching criteria."""
        conn = self._connect()
        try:
            query = [
                "SELECT handoff_id, handoff_version, task_id, status, current_step,",
                "initiator_agent_id, assigned_agent_id, verifier_agent_id,",
                "allowed_verbs_json, allowed_resources_json, prior_crossings_json,",
                "prior_observations_json, assertions_json, contradictions_json,",
                "created_at, expires_at, handoff_hash FROM task_handoffs WHERE 1=1",
            ]
            params: list[Any] = []
            if task_id is not None:
                query.append("AND task_id = ?")
                params.append(task_id)
            if assigned_agent_id is not None:
                query.append("AND assigned_agent_id = ?")
                params.append(assigned_agent_id)
            if status is not None:
                query.append("AND status = ?")
                params.append(status)
            query.append("ORDER BY created_at DESC, rowid DESC LIMIT ?;")
            params.append(limit)

            cur = conn.execute(" ".join(query), params)
            rows = cur.fetchall()
            return [self._row_to_handoff(row) for row in rows]
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to list handoffs: {exc}") from exc
        finally:
            conn.close()

    def update_handoff_status(
        self,
        handoff_id: str,
        status: str,
        *,
        contradictions: tuple[str, ...] | list[str] | None = None,
    ) -> bool:
        """Update handoff status and optional contradiction notes."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            if contradictions is not None:
                cur = conn.execute(
                    """
                    UPDATE task_handoffs
                    SET status = ?, contradictions_json = ?
                    WHERE handoff_id = ?;
                    """,
                    (status, json.dumps(list(contradictions), ensure_ascii=False), handoff_id),
                )
            else:
                cur = conn.execute(
                    "UPDATE task_handoffs SET status = ? WHERE handoff_id = ?;",
                    (status, handoff_id),
                )
            updated = cur.rowcount > 0
            conn.execute("COMMIT;")
            return updated
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            raise ReceiptError(f"Failed to update handoff: {exc}") from exc
        finally:
            conn.close()

    def count_handoffs(self, *, task_id: str | None = None) -> int:
        """Return total count of handoffs, optionally for a specific task."""
        conn = self._connect()
        try:
            if task_id is not None:
                cur = conn.execute(
                    "SELECT COUNT(*) FROM task_handoffs WHERE task_id = ?;", (task_id,)
                )
            else:
                cur = conn.execute("SELECT COUNT(*) FROM task_handoffs;")
            row = cur.fetchone()
            return int(row[0]) if row else 0
        finally:
            conn.close()

    @staticmethod
    def _row_to_handoff(row: tuple[Any, ...]) -> TaskHandoffRecord:
        def _parse_list(raw: Any) -> tuple[str, ...]:
            try:
                res = json.loads(raw) if isinstance(raw, str) else list(raw)
                return tuple(str(x) for x in res)
            except Exception:
                return ()

        try:
            asserts = json.loads(row[12]) if isinstance(row[12], str) else dict(row[12])
        except Exception:
            asserts = {}

        return TaskHandoffRecord(
            handoff_id=str(row[0]),
            handoff_version=str(row[1]),
            task_id=str(row[2]),
            status=row[3],
            current_step=int(row[4]),
            initiator_agent_id=str(row[5]),
            assigned_agent_id=str(row[6]),
            verifier_agent_id=str(row[7]),
            allowed_verbs=_parse_list(row[8]),
            allowed_resources=_parse_list(row[9]),
            prior_crossings=_parse_list(row[10]),
            prior_observations=_parse_list(row[11]),
            assertions=asserts,
            contradictions=_parse_list(row[13]),
            created_at=str(row[14]),
            expires_at=str(row[15]) if row[15] is not None else None,
            handoff_hash=str(row[16]),
        )

    # --- 11. Evidence Records (Phase 5) ---

    def record_evidence(self, evidence: EvidenceRecord) -> EvidenceRecord:
        """Store an immutable evidence record."""
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO evidence_records (
                    evidence_id, crossing_id, tier, trust_domain,
                    collector, observed_at, expires_at, details_json, evidence_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    evidence.evidence_id,
                    evidence.crossing_id,
                    evidence.tier.value,
                    evidence.trust_domain,
                    evidence.collector,
                    evidence.observed_at,
                    evidence.expires_at,
                    canonicalize_json(evidence.details),
                    evidence.evidence_hash,
                ),
            )
            return evidence
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to record evidence: {exc}") from exc
        finally:
            conn.close()

    def get_evidence(self, evidence_id: str) -> EvidenceRecord | None:
        """Fetch an evidence record by its ID."""
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT evidence_id, crossing_id, tier, trust_domain,
                       collector, observed_at, expires_at, details_json, evidence_hash
                FROM evidence_records
                WHERE evidence_id = ? LIMIT 1;
                """,
                (evidence_id,),
            ).fetchone()
            if row is None:
                return None
            return EvidenceRecord(
                evidence_id=str(row[0]),
                crossing_id=str(row[1]),
                tier=EvidenceTier(str(row[2])),
                trust_domain=str(row[3]),
                collector=str(row[4]),
                observed_at=str(row[5]),
                expires_at=str(row[6]) if row[6] is not None else None,
                details=json.loads(str(row[7])),
                evidence_hash=str(row[8]),
            )
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to fetch evidence: {exc}") from exc
        finally:
            conn.close()

    def list_evidence(
        self,
        *,
        crossing_id: str | None = None,
        tier: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EvidenceRecord]:
        """List evidence records filtered by crossing_id and/or tier."""
        conditions: list[str] = []
        params: list[Any] = []
        if crossing_id is not None:
            conditions.append("crossing_id = ?")
            params.append(crossing_id)
        if tier is not None:
            conditions.append("tier = ?")
            params.append(tier)
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"""
            SELECT evidence_id, crossing_id, tier, trust_domain,
                   collector, observed_at, expires_at, details_json, evidence_hash
            FROM evidence_records
            {where_clause}
            ORDER BY observed_at DESC, evidence_id DESC
            LIMIT ? OFFSET ?;
        """  # noqa: S608
        params.extend([max(1, limit), max(0, offset)])
        conn = self._connect()
        try:
            rows = conn.execute(sql, params).fetchall()
            return [
                EvidenceRecord(
                    evidence_id=str(r[0]),
                    crossing_id=str(r[1]),
                    tier=EvidenceTier(str(r[2])),
                    trust_domain=str(r[3]),
                    collector=str(r[4]),
                    observed_at=str(r[5]),
                    expires_at=str(r[6]) if r[6] is not None else None,
                    details=json.loads(str(r[7])),
                    evidence_hash=str(r[8]),
                )
                for r in rows
            ]
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to list evidence records: {exc}") from exc
        finally:
            conn.close()

    def count_evidence(self, *, crossing_id: str | None = None) -> int:
        """Return total number of stored evidence records, optionally filtered by crossing."""
        conn = self._connect()
        try:
            if crossing_id is not None:
                cur = conn.execute(
                    "SELECT COUNT(*) FROM evidence_records WHERE crossing_id = ?;", (crossing_id,)
                )
            else:
                cur = conn.execute("SELECT COUNT(*) FROM evidence_records;")
            row = cur.fetchone()
            return int(row[0]) if row else 0
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to count evidence records: {exc}") from exc
        finally:
            conn.close()

    # --- 12. Persistent Session State (Budgets & Taint) ---

    def get_session_usage(self, session_id: str) -> dict[str, int]:
        """Fetch persisted cumulative session usage."""
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT actions_count, external_calls_count, write_bytes_count
                FROM session_budgets
                WHERE session_id = ? LIMIT 1;
                """,
                (session_id,),
            ).fetchone()
            if row is None:
                return {"actions_count": 0, "external_calls_count": 0, "write_bytes_count": 0}
            return {
                "actions_count": int(row[0]),
                "external_calls_count": int(row[1]),
                "write_bytes_count": int(row[2]),
            }
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to fetch session usage: {exc}") from exc
        finally:
            conn.close()

    def record_session_usage(
        self,
        session_id: str,
        *,
        delta_actions: int = 0,
        delta_external: int = 0,
        delta_bytes: int = 0,
    ) -> dict[str, int]:
        """Atomically increment and persist cumulative session usage."""
        now_ts = utc_now_iso()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            row = conn.execute(
                """
                SELECT actions_count, external_calls_count, write_bytes_count
                FROM session_budgets
                WHERE session_id = ? LIMIT 1;
                """,
                (session_id,),
            ).fetchone()
            if row is None:
                new_actions = delta_actions
                new_external = delta_external
                new_bytes = delta_bytes
                conn.execute(
                    """
                    INSERT INTO session_budgets (
                        session_id, actions_count, external_calls_count,
                        write_bytes_count, updated_at
                    ) VALUES (?, ?, ?, ?, ?);
                    """,
                    (session_id, new_actions, new_external, new_bytes, now_ts),
                )
            else:
                new_actions = int(row[0]) + delta_actions
                new_external = int(row[1]) + delta_external
                new_bytes = int(row[2]) + delta_bytes
                conn.execute(
                    """
                    UPDATE session_budgets
                    SET actions_count = ?, external_calls_count = ?,
                        write_bytes_count = ?, updated_at = ?
                    WHERE session_id = ?;
                    """,
                    (new_actions, new_external, new_bytes, now_ts, session_id),
                )
            conn.execute("COMMIT;")
            return {
                "actions_count": new_actions,
                "external_calls_count": new_external,
                "write_bytes_count": new_bytes,
            }
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            raise ReceiptError(f"Failed to record session usage: {exc}") from exc
        finally:
            conn.close()

    def set_session_taint(self, session_id: str, taint_level: str) -> None:
        """Persist taint status for a session."""
        if taint_level not in ("trusted", "untrusted", "unknown"):
            raise ReceiptError(f"Invalid taint level: {taint_level!r}")
        now_ts = utc_now_iso()
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO session_taints (session_id, taint_level, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    taint_level = excluded.taint_level,
                    updated_at = excluded.updated_at;
                """,
                (session_id, taint_level, now_ts),
            )
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to set session taint: {exc}") from exc
        finally:
            conn.close()

    def get_session_taint(self, session_id: str) -> str | None:
        """Fetch persisted taint status for a session."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT taint_level FROM session_taints WHERE session_id = ? LIMIT 1;",
                (session_id,),
            ).fetchone()
            return str(row[0]) if row else None
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to get session taint: {exc}") from exc
        finally:
            conn.close()

    def list_session_taints(self) -> dict[str, str]:
        """Return all persisted session taints."""
        conn = self._connect()
        try:
            rows = conn.execute("SELECT session_id, taint_level FROM session_taints;").fetchall()
            return {str(r[0]): str(r[1]) for r in rows}
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to list session taints: {exc}") from exc
        finally:
            conn.close()

    def _row_to_lease(self, row: tuple[Any, ...]) -> ResourceLease:
        return ResourceLease(
            lease_id=str(row[0]),
            lease_version=str(row[1]),
            resource=str(row[2]),
            owner_agent_id=str(row[3]),
            session_id=str(row[4]),
            mode=row[5],
            status=row[6],
            acquired_at=str(row[7]),
            expires_at=str(row[8]),
            metadata=json.loads(row[9]),
            lease_hash=str(row[10]),
        )

    def find_resource_conflict(
        self,
        resource: str,
        agent_id: str,
        mode: str = "exclusive",
        now: float | None = None,
    ) -> ResourceLease | None:
        """Check if an active unexpired lease conflicts with the requested resource and mode."""
        curr_time = now if now is not None else time.time()
        now_iso = utc_lease_iso(curr_time)
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT lease_id, lease_version, resource, owner_agent_id,
                       session_id, mode, status, acquired_at, expires_at,
                       metadata_json, lease_hash
                FROM resource_leases
                WHERE status = 'active' AND expires_at > ?;
                """,
                (now_iso,),
            ).fetchall()
            for r in rows:
                lease = self._row_to_lease(r)
                if lease.owner_agent_id == agent_id:
                    continue  # Self-held lease is not a conflict
                if lease.matches_resource(resource) and (
                    mode == "exclusive" or lease.mode == "exclusive"
                ):
                    return lease
            return None
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to check resource conflict: {exc}") from exc
        finally:
            conn.close()

    def acquire_lease(
        self,
        lease: ResourceLease,
        now: float | None = None,
    ) -> ResourceLease:
        """Atomically acquire a resource lease, rejecting if a conflict exists."""
        curr_time = now if now is not None else time.time()
        now_iso = utc_lease_iso(curr_time)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            rows = conn.execute(
                """
                SELECT lease_id, lease_version, resource, owner_agent_id,
                       session_id, mode, status, acquired_at, expires_at,
                       metadata_json, lease_hash
                FROM resource_leases
                WHERE status = 'active' AND expires_at > ?;
                """,
                (now_iso,),
            ).fetchall()
            for r in rows:
                existing = self._row_to_lease(r)
                overlaps = existing.matches_resource(lease.resource) or lease.matches_resource(
                    existing.resource
                )
                if (
                    existing.owner_agent_id != lease.owner_agent_id
                    and overlaps
                    and (lease.mode == "exclusive" or existing.mode == "exclusive")
                ):
                    conn.execute("ROLLBACK;")
                    raise ResourceConflictError(
                        f"Resource '{lease.resource}' conflicts with active lease "
                        f"'{existing.lease_id}' held by agent '{existing.owner_agent_id}' "
                        f"until {existing.expires_at}"
                    )

            conn.execute(
                """
                INSERT INTO resource_leases (
                    lease_id, lease_version, resource, owner_agent_id,
                    session_id, mode, status, acquired_at, expires_at,
                    metadata_json, lease_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    lease.lease_id,
                    lease.lease_version,
                    lease.resource,
                    lease.owner_agent_id,
                    lease.session_id,
                    lease.mode,
                    lease.status,
                    lease.acquired_at,
                    lease.expires_at,
                    json.dumps(lease.metadata),
                    lease.lease_hash,
                ),
            )
            conn.execute("COMMIT;")
            return lease
        except (ResourceConflictError, ReceiptError):
            raise
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            raise ReceiptError(f"Failed to acquire resource lease: {exc}") from exc
        finally:
            conn.close()

    def release_lease(
        self,
        lease_id: str,
        owner_agent_id: str | None = None,
    ) -> bool:
        """Release an active lease. Returns True if released, False if not found/unauthorized."""
        if owner_agent_id is None or not str(owner_agent_id).strip():
            return False

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            row = conn.execute(
                "SELECT owner_agent_id, status FROM resource_leases WHERE lease_id = ?;",
                (lease_id,),
            ).fetchone()
            if not row:
                conn.execute("ROLLBACK;")
                return False
            if str(row[0]) != str(owner_agent_id):
                conn.execute("ROLLBACK;")
                return False
            conn.execute(
                "UPDATE resource_leases SET status = 'released' WHERE lease_id = ?;",
                (lease_id,),
            )
            conn.execute("COMMIT;")
            return True
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK;")
            raise ReceiptError(f"Failed to release lease: {exc}") from exc
        finally:
            conn.close()

    def get_lease(self, lease_id: str) -> ResourceLease | None:
        """Fetch a resource lease by ID."""
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT lease_id, lease_version, resource, owner_agent_id,
                       session_id, mode, status, acquired_at, expires_at,
                       metadata_json, lease_hash
                FROM resource_leases
                WHERE lease_id = ?;
                """,
                (lease_id,),
            ).fetchone()
            return self._row_to_lease(row) if row else None
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to get lease: {exc}") from exc
        finally:
            conn.close()

    def list_leases(
        self,
        *,
        resource: str | None = None,
        owner_agent_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ResourceLease]:
        """List resource leases with optional filtering."""
        conditions: list[str] = []
        params: list[Any] = []
        if resource is not None:
            conditions.append("resource = ?")
            params.append(resource)
        if owner_agent_id is not None:
            conditions.append("owner_agent_id = ?")
            params.append(owner_agent_id)
        if status is not None:
            conditions.append("status = ?")
            params.append(status)
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"""
            SELECT lease_id, lease_version, resource, owner_agent_id,
                   session_id, mode, status, acquired_at, expires_at,
                   metadata_json, lease_hash
            FROM resource_leases
            {where_clause}
            ORDER BY acquired_at DESC, lease_id DESC
            LIMIT ? OFFSET ?;
        """  # noqa: S608
        params.extend([max(1, limit), max(0, offset)])
        conn = self._connect()
        try:
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_lease(r) for r in rows]
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to list leases: {exc}") from exc
        finally:
            conn.close()

    def count_leases(self, status: str | None = None) -> int:
        """Count total leases matching status."""
        conn = self._connect()
        try:
            if status is not None:
                row = conn.execute(
                    "SELECT COUNT(*) FROM resource_leases WHERE status = ?;",
                    (status,),
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) FROM resource_leases;").fetchone()
            return int(row[0]) if row else 0
        except sqlite3.Error as exc:
            raise ReceiptError(f"Failed to count leases: {exc}") from exc
        finally:
            conn.close()


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
