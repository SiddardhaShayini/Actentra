"""Unit tests for Actentra Multi-Agent Resource Coordination, Leases, and Postconditions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema  # type: ignore[import-untyped]
import pytest
from typer.testing import CliRunner

from actentra.boundary import ActionBlockedError, Boundary
from actentra_cli.main import app
from actentra_core.canonicalize import canonicalize_windows_path
from actentra_core.coordination import (
    ResourceConflictError,
    ResourceLease,
    build_lease,
    resource_pattern_matches,
)
from actentra_core.evidence import EvidenceTier
from actentra_core.policy import PolicyPack, parse_policy_dict
from actentra_core.receipts import ReceiptStore
from actentra_core.verdict import Verdict
from actentra_executors.verifiers import WorkspaceFileVerifier
from actentra_gateway.services import AppServices, ExecutorRegistry

runner = CliRunner()


@pytest.fixture
def allow_all_policy() -> PolicyPack:
    raw = {
        "version": 1,
        "policy_id": "test-coord-policy",
        "mode": "enforce",
        "defaults": {"verdict": "deny"},
        "rules": [
            {
                "id": "allow-all-test-rules",
                "match": {"tool": "*"},
                "verdict": "allow",
            }
        ],
    }
    return parse_policy_dict(raw)


def test_lease_schema_conformance_and_hash_integrity(tmp_path: Path) -> None:
    schema_path = Path("spec/lease.v1.schema.json")
    assert schema_path.exists(), "Schema file spec/lease.v1.schema.json must exist"
    with schema_path.open("r", encoding="utf-8") as f:
        schema = json.load(f)

    lease = build_lease(
        resource="path:C:/workspace/data/**",
        owner_agent_id="agent-planner-01",
        session_id="session-coord-1",
        mode="exclusive",
        ttl_seconds=120.0,
        metadata={"priority": "high"},
    )
    data = lease.to_dict()
    # Validate against JSON schema Draft 2020-12
    jsonschema.validate(instance=data, schema=schema)

    # Verify cryptographic hash integrity
    assert lease.verify_integrity() is True

    # Tampering with resource breaks hash integrity
    tampered = ResourceLease(
        lease_id=lease.lease_id,
        lease_version=lease.lease_version,
        resource="path:C:/other/tampered/**",
        owner_agent_id=lease.owner_agent_id,
        session_id=lease.session_id,
        mode=lease.mode,
        status=lease.status,
        acquired_at=lease.acquired_at,
        expires_at=lease.expires_at,
        lease_hash=lease.lease_hash,
        metadata=lease.metadata,
    )
    assert tampered.verify_integrity() is False


def test_resource_pattern_matching() -> None:
    # 1. Exact match (case-insensitive for paths)
    assert resource_pattern_matches("path:C:/work/file.txt", "path:C:/work/file.txt")
    assert resource_pattern_matches("path:C:/work/file.txt", "path:c:/WORK/file.txt")

    # 2. Wildcard pattern
    assert resource_pattern_matches("path:C:/work/**", "path:C:/work/sub/file.txt")
    assert resource_pattern_matches("path:C:/work/*", "path:C:/work/file.txt")

    # 3. Directory prefix
    assert resource_pattern_matches("path:C:/work/", "path:C:/work/sub/file.txt")

    # 4. Non-matching paths
    assert not resource_pattern_matches("path:C:/work/**", "path:C:/other/file.txt")
    assert not resource_pattern_matches("http://api.example.com/*", "http://other.com/call")


def test_lease_storage_and_exclusivity(tmp_path: Path) -> None:
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)

    # Agent A acquires exclusive lease
    lease_a = build_lease(
        resource="path:C:/work/repo/**",
        owner_agent_id="agent-a",
        session_id="sess-a",
        mode="exclusive",
        ttl_seconds=60.0,
    )
    store.acquire_lease(lease_a)
    assert store.count_leases(status="active") == 1

    # Conflict check: Agent B requesting overlapping resource
    conflict = store.find_resource_conflict("path:C:/work/repo/main.py", agent_id="agent-b")
    assert conflict is not None
    assert conflict.lease_id == lease_a.lease_id
    assert conflict.owner_agent_id == "agent-a"

    # Agent B attempting to acquire exclusive lease must be rejected
    lease_b = build_lease(
        resource="path:C:/work/repo/main.py",
        owner_agent_id="agent-b",
        session_id="sess-b",
        mode="exclusive",
        ttl_seconds=60.0,
    )
    with pytest.raises(ResourceConflictError) as exc_info:
        store.acquire_lease(lease_b)
    assert "conflicts with active lease" in str(exc_info.value)

    # Agent A acquiring sub-resource lease is permitted (same owner)
    lease_a2 = build_lease(
        resource="path:C:/work/repo/sub/**",
        owner_agent_id="agent-a",
        session_id="sess-a",
        mode="exclusive",
        ttl_seconds=60.0,
    )
    store.acquire_lease(lease_a2)
    assert store.count_leases(status="active") == 2


def test_shared_leases_coexistence(tmp_path: Path) -> None:
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)

    # Agent A acquires shared lease
    l1 = build_lease(
        resource="path:C:/data/shared/**",
        owner_agent_id="agent-reader-1",
        session_id="sess-1",
        mode="shared",
        ttl_seconds=60.0,
    )
    store.acquire_lease(l1)

    # Agent B acquires shared lease on same resource -> Allowed
    l2 = build_lease(
        resource="path:C:/data/shared/**",
        owner_agent_id="agent-reader-2",
        session_id="sess-2",
        mode="shared",
        ttl_seconds=60.0,
    )
    store.acquire_lease(l2)
    assert store.count_leases(status="active") == 2

    # Agent C attempting exclusive lease on shared resource -> Conflict
    l3 = build_lease(
        resource="path:C:/data/shared/file.txt",
        owner_agent_id="agent-writer",
        session_id="sess-3",
        mode="exclusive",
        ttl_seconds=60.0,
    )
    with pytest.raises(ResourceConflictError):
        store.acquire_lease(l3)


def test_lease_expiration_and_release(tmp_path: Path) -> None:
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)

    # Create lease with 1 second TTL
    lease = build_lease(
        resource="path:C:/temp/**",
        owner_agent_id="agent-worker",
        session_id="sess-temp",
        mode="exclusive",
        ttl_seconds=1.0,
        now=1000.0,
    )
    store.acquire_lease(lease, now=1000.0)

    # Active at time 1000.5
    assert lease.is_active(now=1000.5) is True
    conflict = store.find_resource_conflict("path:C:/temp/f.txt", agent_id="other", now=1000.5)
    assert conflict is not None

    # Expired at time 1002.0
    assert lease.is_active(now=1002.0) is False
    conflict_after = store.find_resource_conflict(
        "path:C:/temp/f.txt", agent_id="other", now=1002.0
    )
    assert conflict_after is None

    # Test explicit release
    lease2 = build_lease(
        resource="path:C:/temp2/**",
        owner_agent_id="agent-worker",
        session_id="sess-temp",
        mode="exclusive",
        ttl_seconds=60.0,
    )
    store.acquire_lease(lease2)
    # Unauthorized release attempt
    assert store.release_lease(lease2.lease_id, owner_agent_id="imposter") is False
    # Authorized release
    assert store.release_lease(lease2.lease_id, owner_agent_id="agent-worker") is True
    assert store.get_lease(lease2.lease_id).status == "released"  # type: ignore[union-attr]


def test_boundary_sdk_coordination_enforcement(
    tmp_path: Path, allow_all_policy: PolicyPack
) -> None:
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)

    b_agent_a = Boundary(
        policy=allow_all_policy,
        receipt_store=store,
        session_id="sess-a",
        agent_id="agent-alice",
    )
    b_agent_b = Boundary(
        policy=allow_all_policy,
        receipt_store=store,
        session_id="sess-b",
        agent_id="agent-bob",
    )

    # Agent A acquires exclusive lease on workspace
    lease = b_agent_a.acquire_lease(
        resource="path:C:/workspace/critical/**",
        mode="exclusive",
        ttl_seconds=120.0,
    )
    assert lease.status == "active"
    assert len(b_agent_a.list_active_leases()) == 1

    # Agent B attempts mutating action (write) on locked resource -> Blocked
    with pytest.raises(ActionBlockedError) as exc_info:
        b_agent_b.execute(
            tool="fs.write",
            verb="write",
            resource="path:C:/workspace/critical/data.bin",
            fn=lambda env, dec: "written",
        )
    assert exc_info.value.decision.verdict == Verdict.DENY
    assert exc_info.value.decision.rule_id == "coordination:resource-locked"
    assert "agent-alice" in exc_info.value.decision.reason

    # Agent B attempts read-only action (read) -> Permitted
    read_res = b_agent_b.execute(
        tool="fs.read",
        verb="read",
        resource="path:C:/workspace/critical/data.bin",
        fn=lambda env, dec: "read_ok",
    )
    assert read_res == "read_ok"

    # Agent A executes mutating write -> Permitted (owner of lease)
    write_res = b_agent_a.execute(
        tool="fs.write",
        verb="write",
        resource="path:C:/workspace/critical/data.bin",
        fn=lambda env, dec: "alice_ok",
    )
    assert write_res == "alice_ok"

    # Agent A releases lease
    assert b_agent_a.release_lease(lease.lease_id) is True

    # Now Agent B can write without conflict
    write_b_res = b_agent_b.execute(
        tool="fs.write",
        verb="write",
        resource="path:C:/workspace/critical/data.bin",
        fn=lambda env, dec: "bob_ok",
    )
    assert write_b_res == "bob_ok"


def test_postcondition_verification_in_boundary(
    tmp_path: Path, allow_all_policy: PolicyPack
) -> None:
    ws_dir = tmp_path / "workspace"
    ws_dir.mkdir(parents=True, exist_ok=True)
    target_file = ws_dir / "output.txt"
    target_res = f"path:{canonicalize_windows_path(str(target_file))}"

    verifier = WorkspaceFileVerifier(ws_dir)
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)

    boundary = Boundary(
        policy=allow_all_policy,
        receipt_store=store,
        session_id="sess-postcond",
        agent_id="agent-writer",
        verifier=verifier,
    )

    def write_op(env: Any, dec: Any) -> dict[str, int]:
        target_file.write_text("verifiable contents", encoding="utf-8")
        return {"bytes": len("verifiable contents")}

    # Execute with automatic postcondition verification
    res = boundary.execute(
        tool="fs.write",
        verb="write",
        resource=target_res,
        fn=write_op,
        verify_postcondition=True,
        postcondition_claim="exists",
    )
    assert res == {"bytes": 19}

    # Verify that an observation record was persisted
    obs_list = store.list_observations()
    assert len(obs_list) == 1
    assert obs_list[0].status == "verified"
    assert obs_list[0].claim == "exists"

    # Verify that an externally_verified EvidenceRecord was created and linked
    ev_list = store.list_evidence(tier="externally_verified")
    assert len(ev_list) == 1
    assert ev_list[0].tier == EvidenceTier.EXTERNALLY_VERIFIED
    assert ev_list[0].trust_domain == "verifier:workspace"

    # Verify causal link linking crossing to observation
    links = store.list_causal_links()
    assert len(links) == 1
    assert links[0].relation == "verifies"
    assert links[0].source_type == "crossing"
    assert links[0].target_type == "observation"


def test_gateway_app_services_lease_coordination(
    tmp_path: Path, allow_all_policy: PolicyPack
) -> None:
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    b = Boundary(policy=allow_all_policy, receipt_store=store)
    services = AppServices(b, executor_registry=ExecutorRegistry())

    # Acquire lease via services
    acq = services.acquire_resource_lease(
        resource="path:C:/shared/db/**",
        owner_agent_id="agent-migrator",
        session_id="sess-mig",
        mode="exclusive",
        ttl_seconds=300.0,
    )
    assert acq["status"] == "acquired"
    lid = acq["lease"]["lease_id"]

    # Verify lease is listed
    leases = services.list_resource_leases()
    assert len(leases) == 1
    assert leases[0]["lease_id"] == lid

    # Conflict check via services
    conflict_acq = services.acquire_resource_lease(
        resource="path:C:/shared/db/users.sql",
        owner_agent_id="agent-writer",
        session_id="sess-w",
        mode="exclusive",
    )
    assert conflict_acq["status"] == "conflict"
    assert "conflicts with active lease" in conflict_acq["error"]

    # Mutating crossing submission conflicts
    crossing_res = services.submit_crossing(
        {
            "tool": "sqlite.query",
            "verb": "write",
            "resource": "path:C:/shared/db/users.sql",
            "agent_id": "agent-writer",
            "session_id": "sess-w",
        }
    )
    assert crossing_res["verdict"] == "deny"
    assert crossing_res["rule_id"] == "coordination:resource-locked"

    # Release lease
    rel = services.release_resource_lease(lid, owner_agent_id="agent-migrator")
    assert rel["released"] is True

    # After release, submission succeeds
    crossing_res2 = services.submit_crossing(
        {
            "tool": "sqlite.query",
            "verb": "write",
            "resource": "path:C:/shared/db/users.sql",
            "agent_id": "agent-writer",
            "session_id": "sess-w",
        }
    )
    assert crossing_res2["verdict"] == "allow"


def test_cli_lease_commands(tmp_path: Path) -> None:
    db_file = tmp_path / "receipts.db"
    ReceiptStore(db_file)  # initializes DB schema

    # 1. Acquire lease via CLI
    res = runner.invoke(
        app,
        [
            "lease",
            "acquire",
            "path:C:/repo/**",
            "--agent",
            "cli-agent",
            "--mode",
            "exclusive",
            "--ttl",
            "120",
            "--db",
            str(db_file),
            "--json",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.output)
    lid = data["lease_id"]
    assert lid.startswith("lease_")

    # 2. List leases via CLI
    res_list = runner.invoke(app, ["lease", "list", "--db", str(db_file)])
    assert res_list.exit_code == 0
    assert lid in res_list.output
    assert "ACTIVE" in res_list.output

    # 3. Show lease via CLI
    res_show = runner.invoke(app, ["lease", "show", lid, "--db", str(db_file)])
    assert res_show.exit_code == 0
    show_data = json.loads(res_show.output)
    assert show_data["lease_id"] == lid

    # 4. Release lease via CLI
    res_rel = runner.invoke(
        app, ["lease", "release", lid, "--agent", "cli-agent", "--db", str(db_file)]
    )
    assert res_rel.exit_code == 0
    assert "successfully released" in res_rel.output
