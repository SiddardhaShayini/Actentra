"""Security regression tests for Finding 03: Warrant max-use counter durability and atomicity.

Verifies:
- Warrant quota durability across process/Boundary restarts (T-03).
- Cache eviction resistance: 1001+ distinct warrant operations do not reset exhausted counters.
- Atomic concurrency enforcement: concurrent threads competing for finite warrants strictly
  respect max_uses with zero overruns.
- Transactional issuance logging in ReceiptStore.
- Unlimited warrants (max_uses=None) are tracked without artificial quotas.
- In-memory registry fallback preserves exhausted quotas without premature eviction.
"""

from __future__ import annotations

import concurrent.futures
import time
from pathlib import Path

import pytest

from actentra import ActionBlockedError, Boundary
from actentra_core.checkpoints import generate_ed25519_keypair
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_core.warrants import (
    WarrantError,
    WarrantRegistry,
    issue_warrant,
)

_POLICY_YAML = """\
version: 1
policy_id: test-warrant-quotas
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-compute
    match: { tool: "compute.*", verb: "exec" }
    verdict: allow
  - id: allow-fs
    match: { tool: "fs.read", verb: "read" }
    verdict: allow
"""


def test_warrant_quota_survives_process_restart(tmp_path: Path) -> None:
    """T-03: Warrant with max_uses=1 used once remains exhausted after process restart."""
    priv, pub = generate_ed25519_keypair()
    db_path = tmp_path / "warrant_restart.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_POLICY_YAML)

    warrant = issue_warrant(
        holder="agent-worker",
        allowed_tools=["compute.add"],
        allowed_resources=["tool:calc"],
        privkey_pem=priv,
        issuer_id="admin-root",
        ttl_seconds=3600.0,
        max_uses=1,
    )

    # 1. First execution in original Boundary instance succeeds
    boundary_1 = Boundary(
        policy=policy,
        receipt_store=store,
        agent_id="agent-worker",
        warrant_public_key=pub,
    )
    res1 = boundary_1.execute(
        tool="compute.add",
        verb="exec",
        resource="tool:calc",
        warrant=warrant,
        fn=lambda env, dec: "result-1",
    )
    assert res1 == "result-1"
    assert boundary_1.warrant_registry is not None
    assert boundary_1.warrant_registry.remaining_uses(warrant) == 0

    # 2. Simulate complete process restart: instantiate new Boundary with fresh memory
    del boundary_1
    reopened_store = ReceiptStore(db_path)
    boundary_2 = Boundary(
        policy=policy,
        receipt_store=reopened_store,
        agent_id="agent-worker",
        warrant_public_key=pub,
    )

    # 3. Assert warrant remains exhausted across restart and second use is denied
    assert boundary_2.warrant_registry is not None
    assert boundary_2.warrant_registry.remaining_uses(warrant) == 0

    with pytest.raises(ActionBlockedError) as exc_info:
        boundary_2.execute(
            tool="compute.add",
            verb="exec",
            resource="tool:calc",
            warrant=warrant,
            fn=lambda env, dec: "result-2",
        )
    assert exc_info.value.decision.rule_id == "warrant:exhausted"
    assert "max uses" in exc_info.value.decision.reason


def test_warrant_quota_resists_cache_eviction_attack(tmp_path: Path) -> None:
    """T-03: Inserting 1001+ distinct warrants into registry cannot evict an exhausted quota."""
    priv, pub = generate_ed25519_keypair()
    db_path = tmp_path / "warrant_eviction.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_POLICY_YAML)

    target_warrant = issue_warrant(
        holder="agent-victim",
        allowed_tools=["fs.read"],
        allowed_resources=["path:C:/data/**"],
        privkey_pem=priv,
        issuer_id="root",
        ttl_seconds=3600.0,
        max_uses=1,
    )

    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        agent_id="agent-victim",
        warrant_public_key=pub,
    )

    # Use target warrant once (exhausting its quota)
    res = boundary.execute(
        tool="fs.read",
        verb="read",
        resource="path:C:/data/config.json",
        warrant=target_warrant,
        fn=lambda env, dec: "conf",
    )
    assert res == "conf"
    assert boundary.warrant_registry is not None
    assert boundary.warrant_registry.remaining_uses(target_warrant) == 0

    # Force eviction by recording 1050 distinct dummy warrants
    for _ in range(1050):
        dummy_warrant = issue_warrant(
            holder="agent-victim",
            allowed_tools=["fs.read"],
            allowed_resources=["path:C:/data/**"],
            privkey_pem=priv,
            issuer_id="flood",
            ttl_seconds=3600.0,
            max_uses=1,
        )
        boundary.warrant_registry.record_use(dummy_warrant)

    # Verify target warrant is STILL exhausted despite 1050 subsequent entries
    assert boundary.warrant_registry.remaining_uses(target_warrant) == 0

    with pytest.raises(ActionBlockedError) as exc_info:
        boundary.execute(
            tool="fs.read",
            verb="read",
            resource="path:C:/data/config.json",
            warrant=target_warrant,
            fn=lambda env, dec: "should-not-run",
        )
    assert exc_info.value.decision.rule_id == "warrant:exhausted"


def test_concurrent_warrant_consumption_strictly_enforces_quota(tmp_path: Path) -> None:
    """T-03: Concurrent threads competing for a finite warrant strictly respect max_uses."""
    priv, pub = generate_ed25519_keypair()
    db_path = tmp_path / "warrant_concurrent.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_POLICY_YAML)

    allowed_quota = 3
    num_threads = 20

    warrant = issue_warrant(
        holder="concurrent-agent",
        allowed_tools=["compute.add"],
        allowed_resources=["tool:calc"],
        privkey_pem=priv,
        issuer_id="root",
        ttl_seconds=3600.0,
        max_uses=allowed_quota,
    )

    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        agent_id="concurrent-agent",
        warrant_public_key=pub,
    )

    success_count = 0
    blocked_count = 0

    def attempt_execution(worker_id: int) -> str:
        return boundary.execute(
            tool="compute.add",
            verb="exec",
            resource="tool:calc",
            warrant=warrant,
            fn=lambda env, dec: f"success-{worker_id}",
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(attempt_execution, i) for i in range(num_threads)]
        for f in concurrent.futures.as_completed(futures):
            try:
                res = f.result()
                assert res.startswith("success-")
                success_count += 1
            except ActionBlockedError as exc:
                assert exc.decision.rule_id == "warrant:exhausted"
                blocked_count += 1

    # Assert exactly allowed_quota succeeded and the rest were blocked
    assert success_count == allowed_quota
    assert blocked_count == num_threads - allowed_quota

    # Verify durable persistence in database
    usage = store.get_warrant_usage(warrant.warrant_id)
    assert usage is not None
    assert usage["consumed_uses"] == allowed_quota
    assert usage["max_uses"] == allowed_quota


def test_standalone_warrant_registry_durability(tmp_path: Path) -> None:
    """WarrantRegistry backed by ReceiptStore persists state across registry instances."""
    priv, _ = generate_ed25519_keypair()
    db_path = tmp_path / "standalone_registry.db"
    store = ReceiptStore(db_path)

    warrant = issue_warrant(
        holder="bot",
        allowed_tools=["calc"],
        allowed_resources=["tool:calc"],
        privkey_pem=priv,
        issuer_id="root",
        max_uses=2,
    )

    # Instance 1: use once
    reg1 = WarrantRegistry(receipt_store=store)
    assert reg1.remaining_uses(warrant) == 2
    reg1.record_use(warrant)
    assert reg1.remaining_uses(warrant) == 1

    # Instance 2: verify count persisted in DB and use second time
    reg2 = WarrantRegistry(receipt_store=store)
    assert reg2.remaining_uses(warrant) == 1
    reg2.record_use(warrant)
    assert reg2.remaining_uses(warrant) == 0

    # Instance 3: verify exhausted state persisted and record_use raises WarrantError
    reg3 = WarrantRegistry(receipt_store=store)
    assert reg3.remaining_uses(warrant) == 0
    with pytest.raises(WarrantError, match="max uses"):
        reg3.record_use(warrant)


def test_warrant_issuance_registration(tmp_path: Path) -> None:
    """Warrant issuance registers metadata transactionally in receipt store."""
    priv, _ = generate_ed25519_keypair()
    db_path = tmp_path / "issuance.db"
    store = ReceiptStore(db_path)

    warrant = issue_warrant(
        holder="agent-lead",
        allowed_tools=["fs.read"],
        allowed_resources=["path:C:/logs/**"],
        privkey_pem=priv,
        issuer_id="security-ops",
        max_uses=5,
        receipt_store=store,
    )

    usage = store.get_warrant_usage(warrant.warrant_id)
    assert usage is not None
    assert usage["warrant_id"] == warrant.warrant_id
    assert usage["issuer"] == "security-ops"
    assert usage["holder"] == "agent-lead"
    assert usage["max_uses"] == 5
    assert usage["consumed_uses"] == 0
    assert usage["expires_at"] == warrant.expires_at


def test_unlimited_warrant_consumption_and_tracking(tmp_path: Path) -> None:
    """Warrants with max_uses=None allow unlimited executions and audit cumulative count."""
    priv, pub = generate_ed25519_keypair()
    db_path = tmp_path / "unlimited.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_POLICY_YAML)

    warrant = issue_warrant(
        holder="worker",
        allowed_tools=["compute.add"],
        allowed_resources=["tool:calc"],
        privkey_pem=priv,
        issuer_id="root",
        ttl_seconds=3600.0,
        max_uses=None,
    )

    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        agent_id="worker",
        warrant_public_key=pub,
    )

    for i in range(10):
        res = boundary.execute(
            tool="compute.add",
            verb="exec",
            resource="tool:calc",
            warrant=warrant,
            fn=lambda env, dec, run_id=i: f"run-{run_id}",
        )
        assert res == f"run-{i}"

    assert boundary.warrant_registry is not None
    assert boundary.warrant_registry.remaining_uses(warrant) is None

    usage = store.get_warrant_usage(warrant.warrant_id)
    assert usage is not None
    assert usage["max_uses"] is None
    assert usage["consumed_uses"] == 10


def test_in_memory_registry_protects_exhausted_quotas_from_eviction() -> None:
    """In-memory fallback never evicts exhausted quotas even under heavy cache pressure."""
    priv, _ = generate_ed25519_keypair()
    registry = WarrantRegistry(max_warrants=5)

    target_warrant = issue_warrant(
        holder="bot",
        allowed_tools=["calc"],
        allowed_resources=["tool:calc"],
        privkey_pem=priv,
        issuer_id="root",
        max_uses=1,
    )

    # Exhaust target warrant
    registry.record_use(target_warrant)
    assert registry.remaining_uses(target_warrant) == 0

    # Add 20 unlimited warrants to force cache eviction attempts
    for _ in range(20):
        unlimited_warrant = issue_warrant(
            holder="bot",
            allowed_tools=["calc"],
            allowed_resources=["tool:calc"],
            privkey_pem=priv,
            issuer_id="root",
            max_uses=None,
        )
        registry.record_use(unlimited_warrant)

    # Target warrant must remain exhausted and cannot be re-used
    assert registry.remaining_uses(target_warrant) == 0
    with pytest.raises(WarrantError, match="max uses"):
        registry.record_use(target_warrant)


def test_adversarial_in_memory_quota_replay_via_finite_warrant_flooding() -> None:
    """R-2 / F-3: Flooding an in-memory registry with finite-use warrants cannot evict quotas."""
    priv, _ = generate_ed25519_keypair()
    reg = WarrantRegistry(max_warrants=2)

    target = issue_warrant(
        holder="target",
        allowed_tools=["fs.read"],
        allowed_resources=["*"],
        privkey_pem=priv,
        issuer_id="root",
        max_uses=1,
    )
    reg.record_use(target)
    assert reg.remaining_uses(target) == 0
    assert reg.is_exhausted(target) is True

    # Flood with multiple additional finite-use warrants beyond capacity
    blocked_count = 0
    for i in range(4):
        w = issue_warrant(
            holder=f"agent-{i}",
            allowed_tools=["fs.read"],
            allowed_resources=["*"],
            privkey_pem=priv,
            issuer_id="root",
            max_uses=1,
        )
        try:
            reg.record_use(w)
        except WarrantError as exc:
            if "saturated" in str(exc).lower():
                blocked_count += 1

    # Capacity enforcement must have kicked in rather than evicting target
    assert blocked_count > 0

    # CRITICAL: Target warrant must remain recorded, remaining_uses MUST be 0, replay must fail
    assert target.warrant_id in reg._uses
    assert reg.remaining_uses(target) == 0
    with pytest.raises(WarrantError, match="max uses .* exceeded"):
        reg.record_use(target)


def test_adversarial_in_memory_capacity_saturation_fails_closed() -> None:
    """When in-memory capacity is full of active finite-use warrants, new ones fail closed."""
    priv, _ = generate_ed25519_keypair()
    reg = WarrantRegistry(max_warrants=3)

    warrants = [
        issue_warrant(
            holder=f"bot-{i}",
            allowed_tools=["calc"],
            allowed_resources=["tool:calc"],
            privkey_pem=priv,
            issuer_id="root",
            max_uses=2,
        )
        for i in range(3)
    ]
    for w in warrants:
        reg.record_use(w)
        assert reg.remaining_uses(w) == 1

    # Attempting to record a 4th warrant must fail closed
    fourth = issue_warrant(
        holder="overflow-bot",
        allowed_tools=["calc"],
        allowed_resources=["tool:calc"],
        privkey_pem=priv,
        issuer_id="root",
        max_uses=1,
    )
    with pytest.raises(WarrantError, match="capacity .* saturated"):
        reg.record_use(fourth)

    # Existing 3 warrants are completely undamaged
    for w in warrants:
        assert reg.remaining_uses(w) == 1


def test_adversarial_in_memory_partial_quota_preservation_under_pressure() -> None:
    """Partially consumed finite quotas are preserved and never reset to initial max_uses."""
    priv, _ = generate_ed25519_keypair()
    reg = WarrantRegistry(max_warrants=3)

    warrant = issue_warrant(
        holder="partial-bot",
        allowed_tools=["calc"],
        allowed_resources=["tool:calc"],
        privkey_pem=priv,
        issuer_id="root",
        max_uses=5,
    )
    reg.record_use(warrant)
    reg.record_use(warrant)
    assert reg.remaining_uses(warrant) == 3

    # Add 2 more warrants to reach max capacity
    for i in range(2):
        w = issue_warrant(
            holder=f"filler-{i}",
            allowed_tools=["calc"],
            allowed_resources=["tool:calc"],
            privkey_pem=priv,
            issuer_id="root",
            max_uses=1,
        )
        reg.record_use(w)

    # Partial warrant quota remains exactly 3
    assert reg.remaining_uses(warrant) == 3


def test_adversarial_in_memory_require_durable_enforcement() -> None:
    """When require_durable=True, finite-use warrants are rejected in in-memory mode."""
    priv, _ = generate_ed25519_keypair()
    reg = WarrantRegistry(max_warrants=10, require_durable=True)
    assert reg.is_durable is False
    assert reg.require_durable is True

    finite_warrant = issue_warrant(
        holder="bot",
        allowed_tools=["calc"],
        allowed_resources=["tool:calc"],
        privkey_pem=priv,
        issuer_id="root",
        max_uses=1,
    )
    with pytest.raises(WarrantError, match="requires durable persistence"):
        reg.record_use(finite_warrant)

    # Unlimited warrant is allowed even with require_durable=True
    unlimited_warrant = issue_warrant(
        holder="bot",
        allowed_tools=["calc"],
        allowed_resources=["tool:calc"],
        privkey_pem=priv,
        issuer_id="root",
        max_uses=None,
    )
    reg.record_use(unlimited_warrant)
    assert reg.remaining_uses(unlimited_warrant) is None


def test_adversarial_expired_warrant_pruning_under_pressure() -> None:
    """Cryptographically expired warrants can be safely pruned to make room."""
    priv, _ = generate_ed25519_keypair()
    reg = WarrantRegistry(max_warrants=2)

    expired = issue_warrant(
        holder="expired-bot",
        allowed_tools=["calc"],
        allowed_resources=["tool:calc"],
        privkey_pem=priv,
        issuer_id="root",
        ttl_seconds=0.01,
        max_uses=1,
    )
    reg.record_use(expired)
    time.sleep(0.05)

    w1 = issue_warrant(
        holder="w1",
        allowed_tools=["calc"],
        allowed_resources=["tool:calc"],
        privkey_pem=priv,
        issuer_id="root",
        ttl_seconds=3600.0,
        max_uses=1,
    )
    reg.record_use(w1)

    # Capacity is 2. The expired warrant should be pruned to make room for w2.
    w2 = issue_warrant(
        holder="w2",
        allowed_tools=["calc"],
        allowed_resources=["tool:calc"],
        privkey_pem=priv,
        issuer_id="root",
        ttl_seconds=3600.0,
        max_uses=1,
    )
    reg.record_use(w2)

    assert expired.warrant_id not in reg._uses
    assert w1.warrant_id in reg._uses
    assert w2.warrant_id in reg._uses
