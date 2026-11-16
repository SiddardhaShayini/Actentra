"""Unit and integration tests for Actentra AppServices and V2 Lifecycle."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from actentra.boundary import Boundary
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore, verify_log
from actentra_gateway.http_service import create_gateway_server
from actentra_gateway.services import AppServices, ExecutorRegistry


def _test_policy() -> str:
    return """
version: 1
policy_id: v2-services-test
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-fs-read
    match: { tool: fs.read, verb: read, resource: "path:**" }
    verdict: allow
  - id: allow-fs-write
    match: { tool: fs.write, verb: write, resource: "path:**" }
    verdict: allow
  - id: ask-fs-delete
    match: { tool: fs.delete, verb: delete, resource: "path:**" }
    verdict: ask
    reason: "File deletion requires human authorization"
"""


def test_persistent_approvals_survive_restart(tmp_path: Path) -> None:
    """Invariant: Pending approvals in SQLite WAL survive process restart."""
    db_path = tmp_path / "persistent_approvals.db"
    store1 = ReceiptStore(db_path)
    policy = load_policy_yaml(_test_policy())
    boundary1 = Boundary(policy=policy, receipt_store=store1, session_id="sess-persist")
    services1 = AppServices(boundary1)

    # 1. Propose an action that produces an ASK verdict
    res1 = services1.submit_crossing(
        {
            "tool": "fs.delete",
            "verb": "delete",
            "resource": "path:C:/work/important.txt",
            "params": {"path": "important.txt"},
            "session_id": "sess-persist",
        }
    )
    assert res1["verdict"] == "ask"
    assert res1["pending_status"] == "pending"
    cid = res1["crossing_id"]
    assert cid

    pending_list1 = services1.list_pending_approvals(status="pending")
    assert len(pending_list1) == 1
    assert pending_list1[0]["crossing_id"] == cid

    # 2. Simulate process shutdown and restart by recreating ReceiptStore & AppServices
    del services1
    del boundary1
    del store1

    store2 = ReceiptStore(db_path)
    boundary2 = Boundary(policy=policy, receipt_store=store2, session_id="sess-persist")
    services2 = AppServices(boundary2)

    # The pending approval must survive!
    pending_list2 = services2.list_pending_approvals(status="pending")
    assert len(pending_list2) == 1
    assert pending_list2[0]["crossing_id"] == cid
    assert pending_list2[0]["tool"] == "fs.delete"

    # 3. Resolve approval in the new process
    app_res = services2.resolve_approval(cid, approved=True)
    assert app_res["status"] == "approved"

    # Pending list should now be empty
    assert len(services2.list_pending_approvals(status="pending")) == 0

    # Resolved record exists in store
    rec = store2.get_pending_approval(cid)
    assert rec is not None
    assert rec.status == "approved"


def test_execute_approved_crossing_survives_restart(tmp_path: Path) -> None:
    """Invariant: An approved crossing can be executed after process restart."""
    db_path = tmp_path / "approved_exec_restart.db"
    store1 = ReceiptStore(db_path)
    policy = load_policy_yaml(_test_policy())
    boundary1 = Boundary(policy=policy, receipt_store=store1, session_id="sess-exec-restart")
    registry1 = ExecutorRegistry()
    test_file = tmp_path / "target.txt"
    test_file.write_text("must be deleted", encoding="utf-8")
    registry1.register_fs(tmp_path)
    services1 = AppServices(boundary1, executor_registry=registry1)

    # 1. Propose action producing ASK
    sub = services1.submit_crossing(
        {
            "tool": "fs.delete",
            "verb": "delete",
            "resource": f"path:{test_file.as_posix()}",
            "params": {"path": "target.txt"},
            "session_id": "sess-exec-restart",
        },
        execute=True,
    )
    cid = sub["crossing_id"]
    assert sub["verdict"] == "ask"
    assert test_file.exists()

    # 2. Operator resolves approval in Process 1 (without immediate execution)
    res = services1.resolve_approval(cid, approved=True, execute=False)
    assert res["status"] == "approved"
    assert test_file.exists()

    # 3. Simulate process crash / restart
    del services1
    del boundary1
    del store1

    # 4. Process 2 starts with same SQLite DB and executor registry
    store2 = ReceiptStore(db_path)
    boundary2 = Boundary(policy=policy, receipt_store=store2, session_id="sess-exec-restart")
    registry2 = ExecutorRegistry()
    registry2.register_fs(tmp_path)
    services2 = AppServices(boundary2, executor_registry=registry2)

    # 5. Execute the approved crossing in the new process!
    exec_res = services2.execute_approved_crossing(cid)
    assert exec_res.get("status") == "success"
    assert not test_file.exists()  # Target file has been deleted by LocalFSExecutor

    # 6. Verify duplicate execution is rejected
    dup_res = services2.execute_approved_crossing(cid)
    assert "error" in dup_res
    assert "not in approved state" in dup_res["error"] or "could not be claimed" in dup_res["error"]

    # 7. Audit log verification
    vr = verify_log(db_path, verify_envelopes=True)
    assert vr.ok


def test_approval_ttl_expiration(tmp_path: Path) -> None:
    """Expired approvals cannot be resolved and are automatically marked expired."""
    db_path = tmp_path / "expiry.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_test_policy())
    boundary = Boundary(policy=policy, receipt_store=store, session_id="sess-exp")
    services = AppServices(boundary, approval_ttl_seconds=0.01)  # 10ms TTL

    res = services.submit_crossing(
        {
            "tool": "fs.delete",
            "verb": "delete",
            "resource": "path:C:/work/temp.txt",
            "params": {"path": "temp.txt"},
            "session_id": "sess-exp",
        }
    )
    cid = res["crossing_id"]

    # Sleep past the TTL
    time.sleep(0.05)

    # Trying to approve an expired crossing fails closed
    app_res = services.resolve_approval(cid, approved=True)
    assert "error" in app_res

    # Record is marked expired
    rec = store.get_pending_approval(cid)
    assert rec is not None
    assert rec.status == "expired"


def test_executor_continuation_and_outcome_receipts(tmp_path: Path) -> None:
    """Registered executors execute authorized actions and commit outcome receipts."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    note_file = ws / "hello.txt"

    db_path = tmp_path / "lifecycle.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_test_policy())
    boundary = Boundary(policy=policy, receipt_store=store, session_id="sess-exec")

    registry = ExecutorRegistry()
    registry.register_fs(ws)

    services = AppServices(boundary, executor_registry=registry)

    # 1. Submit write crossing with execute=True (ALLOW path)
    write_res = services.submit_crossing(
        {
            "tool": "fs.write",
            "verb": "write",
            "resource": f"path:{ws.as_posix()}/hello.txt",
            "params": {"content": "Hello V2!", "path": "hello.txt"},
            "session_id": "sess-exec",
        },
        execute=True,
    )
    assert write_res["verdict"] == "allow"
    assert "outcome" in write_res
    assert write_res["outcome"]["status"] == "success"
    assert note_file.read_text(encoding="utf-8") == "Hello V2!"

    # 2. Submit read crossing with execute=True
    read_res = services.submit_crossing(
        {
            "tool": "fs.read",
            "verb": "read",
            "resource": f"path:{ws.as_posix()}/hello.txt",
            "params": {"path": "hello.txt"},
            "session_id": "sess-exec",
        },
        execute=True,
    )
    assert read_res["verdict"] == "allow"
    assert read_res["outcome"]["result"] == "Hello V2!"

    # 3. Submit delete crossing (ASK path) and approve with execute=True
    del_res = services.submit_crossing(
        {
            "tool": "fs.delete",
            "verb": "delete",
            "resource": f"path:{ws.as_posix()}/hello.txt",
            "params": {"path": "hello.txt"},
            "session_id": "sess-exec",
        }
    )
    assert del_res["verdict"] == "ask"
    del_cid = del_res["crossing_id"]

    # Approve and execute
    app_res = services.resolve_approval(del_cid, approved=True, execute=True)
    assert app_res["status"] == "approved"
    assert "execution" in app_res
    assert app_res["execution"]["status"] == "success"
    assert not note_file.exists()

    # 4. Verify durable hash chain integrity
    vr = verify_log(db_path)
    assert vr.ok is True
    # 3 actions * 2 receipts each (decision + outcome) = 6 records
    assert vr.total_records == 6


def test_external_runner_outcome_recording(tmp_path: Path) -> None:
    """External agent can report execution outcome to complete the audit chain."""
    db_path = tmp_path / "external.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_test_policy())
    boundary = Boundary(policy=policy, receipt_store=store, session_id="sess-ext")
    services = AppServices(boundary)

    # 1. Propose action without gateway execution
    res = services.submit_crossing(
        {
            "tool": "fs.read",
            "verb": "read",
            "resource": "path:C:/external/file.txt",
            "session_id": "sess-ext",
        },
        execute=False,
    )
    assert res["verdict"] == "allow"
    cid = res["crossing_id"]

    # Only decision receipt logged so far
    vr1 = verify_log(db_path)
    assert vr1.ok is True
    assert vr1.total_records == 1

    # 2. External runner executes action and reports outcome
    rec_res = services.record_external_outcome(
        cid,
        status="success",
        result_hash="sha256:" + ("a" * 64),
    )
    assert rec_res["status"] == "recorded"
    assert rec_res["outcome_seq"] == 2

    # Decision + outcome receipts both present
    vr2 = verify_log(db_path)
    assert vr2.ok is True
    assert vr2.total_records == 2


def test_paged_receipts_query_and_search(tmp_path: Path) -> None:
    """Bounded receipt queries support pagination, verdict filters, and text search."""
    db_path = tmp_path / "paged.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_test_policy())
    boundary = Boundary(policy=policy, receipt_store=store, session_id="sess-paged")
    services = AppServices(boundary)

    # Generate 5 actions
    for i in range(5):
        services.submit_crossing(
            {
                "tool": "fs.read",
                "verb": "read",
                "resource": f"path:C:/work/file_{i}.txt",
                "session_id": "sess-paged",
            }
        )

    # Query with limit=2, offset=0
    q1 = services.query_receipts(limit=2, offset=0)
    assert len(q1["records"]) == 2
    assert q1["total_count"] == 5

    # Query with limit=2, offset=4
    q2 = services.query_receipts(limit=2, offset=4)
    assert len(q2["records"]) == 1
    assert q2["total_count"] == 5

    # Search filter
    q_search = services.query_receipts(search="file_3")
    assert len(q_search["records"]) == 1
    raw_env = store.get_envelope(q_search["records"][0]["crossing_id"])
    assert raw_env is not None and "file_3" in raw_env["action"]["resource"]


def test_policy_canary_and_simulation(tmp_path: Path) -> None:
    """Canary diff simulation detects regressions against historical receipts."""
    db_path = tmp_path / "canary_test.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_test_policy())
    boundary = Boundary(policy=policy, receipt_store=store, session_id="sess-canary")
    services = AppServices(boundary)

    # Log an action with current policy
    services.submit_crossing(
        {
            "tool": "fs.read",
            "verb": "read",
            "resource": "path:C:/work/doc.txt",
            "session_id": "sess-canary",
        }
    )

    # Candidate policy that restricts fs.read to deny
    restrictive_yaml = """
version: 1
policy_id: restrictive-policy
mode: enforce
defaults: { verdict: deny }
rules: []
"""
    canary_res = services.run_canary_on_candidate(restrictive_yaml)
    assert canary_res["total_evaluated"] == 1
    assert canary_res["more_restrictive_count"] == 1
    assert canary_res["less_restrictive_count"] == 0

    # Dry-run simulator
    sim = services.simulate_dry_run(
        tool="fs.read",
        verb="read",
        resource="path:C:/work/doc.txt",
    )
    assert sim["verdict"] == "allow"
    assert sim["rule_id"] == "allow-fs-read"


def test_loopback_binding_and_token_auth(tmp_path: Path) -> None:
    """Binding to non-loopback fails closed without explicit flag and token."""
    db_path = tmp_path / "security.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_test_policy())
    boundary = Boundary(policy=policy, receipt_store=store)

    # Binding to 0.0.0.0 without unsafe flag must raise ValueError
    with pytest.raises(ValueError, match="Refusing to bind Actentra Gateway"):
        create_gateway_server(boundary, host="0.0.0.0", port=0, unsafe_allow_remote=False)

    # Binding with explicit unsafe_allow_remote is permitted
    srv = create_gateway_server(
        boundary,
        host="0.0.0.0",
        port=0,
        auth_token="secret-token-123",
        unsafe_allow_remote=True,
    )
    assert srv.auth_token == "secret-token-123"
    srv.server_close()


def test_export_audit_bundle(tmp_path: Path) -> None:
    """Offline audit bundle includes active policy, receipts, and verification metadata."""
    db_path = tmp_path / "bundle.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_test_policy())
    boundary = Boundary(policy=policy, receipt_store=store)
    services = AppServices(boundary)

    services.submit_crossing(
        {"tool": "fs.read", "verb": "read", "resource": "path:C:/work/test.txt"}
    )

    bundle_path = tmp_path / "audit_bundle.json"
    bundle = services.export_audit_bundle(out_path=bundle_path)

    assert bundle_path.exists()
    assert bundle["policy"]["id"] == "v2-services-test"
    assert bundle["integrity"]["ok"] is True
    assert len(bundle["receipts"]) == 1

    loaded = json.loads(bundle_path.read_text(encoding="utf-8"))
    assert loaded["policy"]["id"] == "v2-services-test"
