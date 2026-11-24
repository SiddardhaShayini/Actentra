"""Comprehensive test suite for Phase 7: Production Reliability Engineering.

Covers:
1. Action Execution Lifecycle State Machine (enforcement, legal vs illegal transitions).
2. Durable Idempotency (deduplication, conflict detection, in-flight blocks, reconciliation).
3. Crash Recovery & Unified System Reconciliation (executing actions, claims, leases, approvals).
4. Database Resilience & Integrity Verification
   (PRAGMA check, sequence continuity, fail-closed on corrupt DB).
5. Concurrency Hardening (race-free idempotency registration and transitions).
6. Observability & Operational Telemetry (counters, latencies, secret redaction).
"""

from __future__ import annotations

import concurrent.futures
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from actentra.boundary import Boundary
from actentra_core.envelope import build_envelope
from actentra_core.identity import make_local_caller_context
from actentra_core.lifecycle import (
    DatabaseUnavailableError,
    IdempotencyConflictError,
    IdempotencyInFlightError,
    InvalidStateTransitionError,
    ReconciliationRequiredError,
)
from actentra_core.observability import (
    OperationalMetrics,
    sanitize_operational_data,
)
from actentra_core.policy import PolicyPack, parse_policy_dict
from actentra_core.receipts import ReceiptStore
from actentra_core.verdict import Decision, Verdict
from actentra_gateway.services import AppServices, ExecutorRegistry


def _make_allow_policy() -> PolicyPack:
    return parse_policy_dict(
        {
            "version": 1,
            "policy_id": "phase7-policy",
            "mode": "enforce",
            "defaults": {"verdict": "deny", "reason": "default deny"},
            "rules": [
                {
                    "id": "allow-tools",
                    "verdict": "allow",
                    "match": {"tool": "*"},
                }
            ],
        }
    )


def _make_ask_policy() -> PolicyPack:
    return parse_policy_dict(
        {
            "version": 1,
            "policy_id": "phase7-ask-policy",
            "mode": "enforce",
            "defaults": {"verdict": "deny", "reason": "default deny"},
            "rules": [
                {
                    "id": "ask-critical",
                    "verdict": "ask",
                    "match": {"tool": "fs.*", "verb": "delete"},
                    "reason": "Human approval required for deletion",
                },
                {
                    "id": "allow-reads",
                    "verdict": "allow",
                    "match": {"tool": "fs.*", "verb": "read"},
                },
            ],
        }
    )


# =============================================================================
# 1. Action Execution Lifecycle State Machine Tests
# =============================================================================


def test_lifecycle_happy_path_transitions(tmp_path: Path) -> None:
    db_file = tmp_path / "lifecycle.db"
    store = ReceiptStore(db_file)
    crossing_id = "cross_001"
    session_id = "sess_001"
    principal_id = "agent_alpha"
    canonical_hash = "sha256:" + ("a" * 64)

    # 1. Create lifecycle
    rec = store.create_action_lifecycle(
        crossing_id=crossing_id,
        session_id=session_id,
        principal_id=principal_id,
        canonical_hash=canonical_hash,
        idempotency_key="idemp_001",
    )
    assert rec.current_state == "created"
    assert rec.crossing_id == crossing_id

    # 2. Transition created -> authorized
    rec2 = store.transition_action_state(
        crossing_id, "authorized", actor_id="policy_engine", reason="policy_allow"
    )
    assert rec2.current_state == "authorized"

    # 3. Transition authorized -> claimed
    rec3 = store.transition_action_state(
        crossing_id, "claimed", actor_id=principal_id, reason="claim_issued"
    )
    assert rec3.current_state == "claimed"

    # 4. Transition claimed -> executing
    rec4 = store.transition_action_state(
        crossing_id, "executing", actor_id=principal_id, reason="dispatch"
    )
    assert rec4.current_state == "executing"

    # 5. Transition executing -> verification_pending
    rec5 = store.transition_action_state(
        crossing_id, "verification_pending", actor_id=principal_id, reason="verify"
    )
    assert rec5.current_state == "verification_pending"

    # 6. Transition verification_pending -> succeeded
    rec6 = store.transition_action_state(
        crossing_id, "succeeded", actor_id="verifier_01", reason="verified"
    )
    assert rec6.current_state == "succeeded"

    # Audit trail validation
    transitions = store.list_action_transitions(crossing_id)
    assert len(transitions) == 6  # 1 initial + 5 transitions
    assert transitions[0].to_state == "created"
    assert transitions[1].from_state == "created" and transitions[1].to_state == "authorized"
    assert transitions[2].from_state == "authorized" and transitions[2].to_state == "claimed"
    assert transitions[3].from_state == "claimed" and transitions[3].to_state == "executing"
    assert (
        transitions[4].from_state == "executing"
        and transitions[4].to_state == "verification_pending"
    )
    assert (
        transitions[5].from_state == "verification_pending"
        and transitions[5].to_state == "succeeded"
    )


def test_lifecycle_rejection_of_illegal_transitions(tmp_path: Path) -> None:
    db_file = tmp_path / "lifecycle_illegal.db"
    store = ReceiptStore(db_file)
    crossing_id = "cross_illegal"

    store.create_action_lifecycle(
        crossing_id=crossing_id,
        session_id="sess_01",
        principal_id="agent_alpha",
        canonical_hash="sha256:" + ("b" * 64),
    )

    # Illegal transition: created directly to succeeded
    with pytest.raises(InvalidStateTransitionError) as exc_info:
        store.transition_action_state(crossing_id, "succeeded", actor_id="agent_alpha")
    assert exc_info.value.from_state == "created"
    assert exc_info.value.to_state == "succeeded"

    # Transition to authorized
    store.transition_action_state(crossing_id, "authorized", actor_id="policy")

    # Illegal transition: authorized directly to executing (skipping claim)
    with pytest.raises(InvalidStateTransitionError) as exc_info2:
        store.transition_action_state(crossing_id, "executing", actor_id="agent_alpha")
    assert exc_info2.value.from_state == "authorized"
    assert exc_info2.value.to_state == "executing"

    # Complete to failed (terminal)
    store.transition_action_state(crossing_id, "failed", actor_id="policy", reason="denied")

    # Illegal transition from terminal state
    with pytest.raises(InvalidStateTransitionError) as exc_info3:
        store.transition_action_state(crossing_id, "authorized", actor_id="agent_alpha")
    assert exc_info3.value.from_state == "failed"


def test_lifecycle_reconciliation_flow(tmp_path: Path) -> None:
    db_file = tmp_path / "lifecycle_recon.db"
    store = ReceiptStore(db_file)
    crossing_id = "cross_recon"

    store.create_action_lifecycle(
        crossing_id=crossing_id,
        session_id="sess_01",
        principal_id="agent_alpha",
        canonical_hash="sha256:" + ("c" * 64),
    )
    store.transition_action_state(crossing_id, "authorized", actor_id="policy")
    store.transition_action_state(crossing_id, "claimed", actor_id="agent_alpha")
    store.transition_action_state(crossing_id, "executing", actor_id="agent_alpha")

    # Unexpected crash/timeout -> unknown
    store.transition_action_state(crossing_id, "unknown", actor_id="system", reason="timeout")

    # Unknown -> reconciliation_required
    store.transition_action_state(
        crossing_id, "reconciliation_required", actor_id="reconciler", reason="investigate"
    )

    # Reconciliation completes -> succeeded
    final_rec = store.transition_action_state(
        crossing_id, "succeeded", actor_id="reconciler", reason="evidence_confirmed"
    )
    assert final_rec.current_state == "succeeded"


# =============================================================================
# 2. Durable Idempotency Tests
# =============================================================================


def test_idempotency_cached_success_replay(tmp_path: Path) -> None:
    db_file = tmp_path / "idemp_cached.db"
    store = ReceiptStore(db_file)
    policy = _make_allow_policy()

    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        session_id="sess_01",
        agent_id="test_agent",
    )

    call_count = 0

    def mock_tool(envelope: Any, decision: Any) -> dict[str, str]:
        nonlocal call_count
        call_count += 1
        return {"data": "file_contents_123"}

    # First execution with idempotency key
    result1 = boundary.execute(
        tool="fs.read",
        verb="read",
        resource="/tmp/file.txt",
        params={"flag": 1},
        fn=mock_tool,
        idempotency_key="idemp_key_unique_01",
    )
    assert call_count == 1
    assert result1 == {"data": "file_contents_123"}

    # Replay execution with exact same key and parameters
    result2 = boundary.execute(
        tool="fs.read",
        verb="read",
        resource="/tmp/file.txt",
        params={"flag": 1},
        fn=mock_tool,
        idempotency_key="idemp_key_unique_01",
    )
    # Crucial Invariant I16: Tool was NOT called again; cached result returned!
    assert call_count == 1
    assert result2 == {"data": "file_contents_123"}


def test_idempotency_conflict_rejection(tmp_path: Path) -> None:
    db_file = tmp_path / "idemp_conflict.db"
    store = ReceiptStore(db_file)
    policy = _make_allow_policy()

    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        session_id="sess_01",
        agent_id="test_agent",
    )

    # First execution with key-A
    boundary.execute(
        tool="fs.write",
        verb="write",
        resource="/tmp/file1.txt",
        params={"content": "hello"},
        fn=lambda env, dec: "written_file1",
        idempotency_key="shared_idemp_key",
    )

    # Attempt second execution with same key but DIFFERENT parameters (different canonical hash)
    with pytest.raises(IdempotencyConflictError) as exc_info:
        boundary.execute(
            tool="fs.write",
            verb="write",
            resource="/tmp/file2.txt",  # Different resource!
            params={"content": "differing"},
            fn=lambda env, dec: "written_file2",
            idempotency_key="shared_idemp_key",
        )
    assert "shared_idemp_key" in str(exc_info.value)
    assert "Action payload mismatch" in str(exc_info.value)


def test_idempotency_in_flight_concurrency_block(tmp_path: Path) -> None:
    db_file = tmp_path / "idemp_inflight.db"
    store = ReceiptStore(db_file)

    # Register an idempotency key as in_flight
    res1 = store.register_idempotency_key(
        idempotency_key="in_flight_key",
        principal_id="agent_1",
        canonical_hash="sha256:" + ("d" * 64),
        tool="fs.write",
        verb="write",
        crossing_id="cross_fl_01",
        ttl_seconds=300.0,
    )
    assert res1 is None  # Registered as in_flight

    # Attempt concurrent registration while in_flight
    with pytest.raises(IdempotencyInFlightError) as exc_info:
        store.register_idempotency_key(
            idempotency_key="in_flight_key",
            principal_id="agent_1",
            canonical_hash="sha256:" + ("d" * 64),
            tool="fs.write",
            verb="write",
            crossing_id="cross_fl_02",
        )
    assert "in_flight_key" in str(exc_info.value)
    assert "cross_fl_01" in str(exc_info.value)


def test_idempotency_reconciliation_required_block(tmp_path: Path) -> None:
    db_file = tmp_path / "idemp_recon.db"
    store = ReceiptStore(db_file)

    # Simulate an expired in-flight record
    store.register_idempotency_key(
        idempotency_key="expired_flight_key",
        principal_id="agent_1",
        canonical_hash="sha256:" + ("e" * 64),
        tool="fs.write",
        verb="write",
        crossing_id="cross_exp_01",
        ttl_seconds=-10.0,  # Expired in past
    )

    # Replay should detect expired in-flight and raise ReconciliationRequiredError
    with pytest.raises(ReconciliationRequiredError) as exc_info:
        store.register_idempotency_key(
            idempotency_key="expired_flight_key",
            principal_id="agent_1",
            canonical_hash="sha256:" + ("e" * 64),
            tool="fs.write",
            verb="write",
            crossing_id="cross_exp_02",
        )
    assert "reconciliation is required before replay" in str(exc_info.value)


# =============================================================================
# 3. Crash Recovery & Unified System Reconciliation Tests
# =============================================================================


def test_crash_recovery_during_execution(tmp_path: Path) -> None:
    db_file = tmp_path / "crash_exec.db"
    store = ReceiptStore(db_file)

    # Simulate in-flight action right before crash:
    # 1. Decision receipt recorded (ALLOW)
    env = build_envelope(
        tool="sql.execute",
        verb="write",
        resource="app_db",
        params={"query": "UPDATE balance SET amount = 0"},
        session_id="sess_crashed",
        agent_id="finance_bot",
    )
    decision = Decision(
        verdict=Verdict.ALLOW,
        rule_id="finance:allow",
        reason="permitted",
        policy_version="1.0.0",
        canonical_hash=env.canonical_hash,
    )
    store.record_decision(env, decision)

    # 2. Action lifecycle stuck in EXECUTING
    store.create_action_lifecycle(
        crossing_id=env.crossing_id,
        session_id=env.session_id,
        principal_id="finance_bot",
        canonical_hash=env.canonical_hash,
        idempotency_key="transfer_txn_999",
        initial_state="executing",
    )

    # 3. Idempotency record stuck in IN_FLIGHT
    store.register_idempotency_key(
        idempotency_key="transfer_txn_999",
        principal_id="finance_bot",
        canonical_hash=env.canonical_hash,
        tool="sql.execute",
        verb="write",
        crossing_id=env.crossing_id,
    )

    # 4. Claim issued but not consumed
    store.issue_execution_claim(
        crossing_id=env.crossing_id,
        executor_principal_id="finance_bot",
        session_id=env.session_id,
        canonical_hash=env.canonical_hash,
        ttl_seconds=-5.0,  # expired
    )

    # Simulate service restart: run recover_system_state()
    recovery_report = store.recover_system_state()

    assert recovery_report["actions_reconciled"] >= 1
    assert recovery_report["idempotency_reconciled"] >= 1
    assert recovery_report["outcomes_recovered"] >= 1
    assert recovery_report["claims_expired"] >= 1

    # Verify lifecycle state transitioned to reconciliation_required
    lf = store.get_action_lifecycle(env.crossing_id)
    assert lf is not None
    assert lf.current_state == "reconciliation_required"

    # Verify idempotency record transitioned to reconciliation_required
    idemp = store.get_idempotency_record("finance_bot", "transfer_txn_999")
    assert idemp is not None
    assert idemp.status == "reconciliation_required"

    # Verify outcome receipt was durably recorded as 'unknown'
    outcome = store.get_outcome_receipt(env.crossing_id)
    assert outcome is not None
    assert outcome.status == "unknown"


def test_crash_recovery_temp_files_cleanup(tmp_path: Path) -> None:
    db_file = tmp_path / "clean_temp.db"
    store = ReceiptStore(db_file)

    # Create dummy leftover temporary checkpoint files
    tmp1 = tmp_path / ".tmp_checkpoint_123.bin"
    tmp2 = tmp_path / ".tmp_export_456.jsonl"
    tmp1.write_text("partial checkpoint data")
    tmp2.write_text("partial export data")
    assert tmp1.exists() and tmp2.exists()

    report = store.recover_system_state()
    assert report["temporary_files_cleaned"] >= 2
    assert not tmp1.exists()
    assert not tmp2.exists()


# =============================================================================
# 4. Database Resilience & Integrity Verification Tests
# =============================================================================


def test_database_integrity_validation_ok(tmp_path: Path) -> None:
    db_file = tmp_path / "integrity_ok.db"
    store = ReceiptStore(db_file)

    # Record some receipts
    for i in range(5):
        env = build_envelope(
            tool="fs.read",
            verb="read",
            resource=f"/tmp/file_{i}.txt",
            session_id="sess_01",
            agent_id="agent_1",
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="allow_all",
            reason="ok",
            policy_version="1.0.0",
            canonical_hash=env.canonical_hash,
        )
        store.record_decision(env, dec)
        store.record_outcome(
            crossing_id=env.crossing_id,
            session_id=env.session_id,
            canonical_hash=env.canonical_hash,
            policy_version="1.0.0",
            status="success",
        )

    ok, msg = store.validate_database_integrity()
    assert ok is True
    assert msg == "OK"


def test_database_integrity_sequence_gap_detection(tmp_path: Path) -> None:
    db_file = tmp_path / "integrity_gap.db"
    store = ReceiptStore(db_file)

    # Record 3 receipts
    for i in range(3):
        env = build_envelope(
            tool="fs.read",
            verb="read",
            resource=f"/tmp/file_{i}.txt",
            session_id="sess_01",
            agent_id="agent_1",
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id="allow_all",
            reason="ok",
            policy_version="1.0.0",
            canonical_hash=env.canonical_hash,
        )
        store.record_decision(env, dec)

    # Artificially delete sequence 2
    conn = sqlite3.connect(db_file)
    conn.execute("DELETE FROM receipts WHERE seq = 2;")
    conn.commit()
    conn.close()

    ok, msg = store.validate_database_integrity()
    assert ok is False
    assert "Sequence gap in receipts" in msg


def test_database_corruption_fail_closed(tmp_path: Path) -> None:
    db_file = tmp_path / "corrupt.db"
    db_file.write_bytes(b"NOT A REAL SQLITE DATABASE HEADER GIBBERISH")

    # ReceiptStore must fail closed with DatabaseUnavailableError
    with pytest.raises(DatabaseUnavailableError):
        ReceiptStore(db_file)


# =============================================================================
# 5. Concurrency Hardening Tests
# =============================================================================


def test_concurrent_idempotency_registration(tmp_path: Path) -> None:
    db_file = tmp_path / "concurrent_idemp.db"
    store = ReceiptStore(db_file)
    idemp_key = "concurrent_key_001"
    principal = "worker_agent"
    canon_hash = "sha256:" + ("f" * 64)

    results: list[Any] = []
    errors: list[Exception] = []

    def attempt_registration(worker_id: int) -> None:
        try:
            res = store.register_idempotency_key(
                idempotency_key=idemp_key,
                principal_id=principal,
                canonical_hash=canon_hash,
                tool="sql.execute",
                verb="write",
                crossing_id=f"crossing_{worker_id}",
            )
            results.append((worker_id, res))
        except Exception as exc:
            errors.append(exc)

    threads = 15
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(attempt_registration, i) for i in range(threads)]
        concurrent.futures.wait(futures)

    # Exactly one thread should succeed in registering as in_flight (returning None)
    successes = [r for r in results if r[1] is None]
    assert len(successes) == 1

    # All other threads must be safely rejected with IdempotencyInFlightError
    assert len(errors) == threads - 1
    assert all(isinstance(e, IdempotencyInFlightError) for e in errors)


# =============================================================================
# 6. Observability & Operational Metrics Tests
# =============================================================================


def test_operational_metrics_collection_and_sanitization() -> None:
    metrics = OperationalMetrics()
    metrics.increment("crossings_total", 10)
    metrics.increment("crossings_allowed", 8)
    metrics.increment("crossings_denied", 2)
    metrics.increment("executions_dispatched", 5)
    metrics.increment("executions_succeeded", 5)
    metrics.increment("idempotency_registered", 3)
    metrics.increment("idempotency_cached_hits", 2)

    metrics.record_latency("tool:fs.read", 0.012)
    metrics.record_latency("tool:fs.read", 0.024)

    snap = metrics.snapshot()
    assert snap["crossings"]["total"] == 10
    assert snap["crossings"]["allowed"] == 8
    assert snap["crossings"]["denied"] == 2
    assert snap["executions"]["dispatched"] == 5
    assert snap["executions"]["succeeded"] == 5
    assert snap["idempotency"]["registered"] == 3
    assert snap["idempotency"]["cached_hits"] == 2
    assert "tool:fs.read" in snap["latencies"]
    assert snap["latencies"]["tool:fs.read"]["count"] == 2

    # Verify secret scrubbing
    raw_payload = {
        "user_id": "usr_123",
        "bearer_token": "secret_token_12345",
        "api_key": "sk-secret-key",
        "nested": {"password": "supersecretpassword", "ok_val": 42},
    }
    cleaned = sanitize_operational_data(raw_payload)
    assert cleaned["user_id"] == "usr_123"
    assert cleaned["bearer_token"] == "[REDACTED]"
    assert cleaned["api_key"] == "[REDACTED]"
    assert cleaned["nested"]["password"] == "[REDACTED]"
    assert cleaned["nested"]["ok_val"] == 42


# =============================================================================
# 7. Gateway Services Integration Test for Phase 7
# =============================================================================


def test_gateway_services_phase7_idempotency_and_metrics(tmp_path: Path) -> None:
    db_file = tmp_path / "gateway_phase7.db"
    store = ReceiptStore(db_file)
    policy = _make_allow_policy()
    boundary = Boundary(policy=policy, receipt_store=store)

    registry = ExecutorRegistry()
    registry.register("echo.tool", lambda env, dec: f"echoed:{env.action.params.get('msg')}")

    services = AppServices(boundary, executor_registry=registry)

    # Health check reflects database health
    health = services.get_health()
    assert health["status"] == "ok"
    assert health["db_integrity_ok"] is True
    assert health["db_status"] == "healthy"

    caller_ctx = make_local_caller_context(principal_id="test_operator")

    # 1. First execution with idempotency key
    payload = {
        "tool": "echo.tool",
        "verb": "exec",
        "resource": "local_echo",
        "params": {"msg": "hello_world"},
        "idempotency_key": "gw_key_101",
    }
    resp1 = services.submit_crossing(payload, execute=True, caller_context=caller_ctx)
    assert resp1["verdict"] == "allow"
    assert resp1["executed"] is True
    assert resp1["outcome"]["result"] == "echoed:hello_world"

    # 2. Replay returns cached outcome directly without re-execution
    resp2 = services.submit_crossing(payload, execute=True, caller_context=caller_ctx)
    assert resp2["verdict"] == "allow"
    assert resp2["executed"] is True
    assert resp2["cached"] is True
    assert resp2["outcome"]["result"] == "echoed:hello_world"

    # 3. Conflict rejection via gateway
    conflict_payload = {
        "tool": "echo.tool",
        "verb": "exec",
        "resource": "local_echo",
        "params": {"msg": "DIFFERING_MSG"},
        "idempotency_key": "gw_key_101",
    }
    resp_conflict = services.submit_crossing(
        conflict_payload, execute=True, caller_context=caller_ctx
    )
    assert resp_conflict["verdict"] == "hold"
    assert "IdempotencyConflictError" in resp_conflict["rule_id"]

    # 4. Metrics endpoint reflects operations
    metrics = services.get_metrics()
    assert metrics["storage"]["database_healthy"] is True
    assert metrics["crossings"]["total"] >= 1
    assert metrics["executions"]["dispatched"] >= 1
    assert metrics["idempotency"]["cached_hits"] >= 1
