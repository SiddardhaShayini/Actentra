"""Unit tests for Actentra Evidence Taxonomy, Identity Boundaries, and Durable State (V5)."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema  # type: ignore[import-untyped]
import pytest

from actentra.boundary import ActionBlockedError, Boundary
from actentra_core.canary import run_policy_canary
from actentra_core.envelope import ProvenanceItem, build_envelope
from actentra_core.evidence import (
    EvidenceTier,
    build_evidence_record,
    compute_evidence_hash,
)
from actentra_core.identity import (
    IdentitySecurityError,
    make_local_caller_context,
    resolve_http_caller_context,
)
from actentra_core.policy import PolicyEngine, load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_core.verdict import Verdict
from actentra_gateway.services import AppServices, ExecutorRegistry

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_evidence_record_schema_and_hashing(tmp_path: Path) -> None:
    schema = json.loads(
        (REPO_ROOT / "spec" / "evidence.v1.schema.json").read_text(encoding="utf-8")
    )

    ev = build_evidence_record(
        crossing_id="01JCANARYCROSSING12345678",
        tier=EvidenceTier.LOCALLY_OBSERVED,
        trust_domain="local_boundary",
        collector="executor:fs.write",
        details={"bytes_written": 128, "target": "work/test.txt"},
    )

    ev_dict = ev.to_dict()
    jsonschema.validate(instance=ev_dict, schema=schema)

    # Deterministic hash recomputation
    computed = compute_evidence_hash(
        evidence_id=ev.evidence_id,
        crossing_id=ev.crossing_id,
        tier=ev.tier.value,
        trust_domain=ev.trust_domain,
        collector=ev.collector,
        observed_at=ev.observed_at,
        expires_at=ev.expires_at,
        details=ev.details,
    )
    assert ev.evidence_hash == computed
    assert ev.is_fresh() is True


def test_evidence_freshness_and_expiry() -> None:
    ev = build_evidence_record(
        crossing_id="01JCANARYCROSSING12345678",
        tier=EvidenceTier.EXTERNALLY_VERIFIED,
        trust_domain="verifier:workspace",
        collector="WorkspaceFileVerifier",
        observed_at="2026-11-17T12:00:00.000Z",
        expires_at="2026-11-17T12:05:00.000Z",
    )
    # Check fresh before expiry
    assert ev.is_fresh(as_of="2026-11-17T12:04:00.000Z") is True
    # Check stale after expiry
    assert ev.is_fresh(as_of="2026-11-17T12:06:00.000Z") is False


def test_evidence_store_persistence(tmp_path: Path) -> None:
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)

    ev1 = build_evidence_record(
        crossing_id="01JTESTCROSSING111111111111",
        tier=EvidenceTier.LOCALLY_OBSERVED,
        trust_domain="local_boundary",
        collector="executor:fs.write",
    )
    ev2 = build_evidence_record(
        crossing_id="01JTESTCROSSING111111111111",
        tier=EvidenceTier.EXTERNALLY_VERIFIED,
        trust_domain="verifier:workspace",
        collector="WorkspaceFileVerifier",
    )
    ev3 = build_evidence_record(
        crossing_id="01JTESTCROSSING222222222222",
        tier=EvidenceTier.CALLER_REPORTED,
        trust_domain="external_caller",
        collector="http_client",
    )

    store.record_evidence(ev1)
    store.record_evidence(ev2)
    store.record_evidence(ev3)

    assert store.count_evidence() == 3
    assert store.count_evidence(crossing_id="01JTESTCROSSING111111111111") == 2

    fetched = store.get_evidence(ev1.evidence_id)
    assert fetched is not None
    assert fetched.tier == EvidenceTier.LOCALLY_OBSERVED
    assert fetched.evidence_hash == ev1.evidence_hash

    # Filtered listing
    by_crossing = store.list_evidence(crossing_id="01JTESTCROSSING111111111111")
    assert len(by_crossing) == 2

    by_tier = store.list_evidence(tier="caller_reported")
    assert len(by_tier) == 1
    assert by_tier[0].evidence_id == ev3.evidence_id


def test_receipt_records_carry_evidence_status(tmp_path: Path) -> None:
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml("""
version: 1
defaults: { verdict: deny }
rules:
  - id: allow-fs
    match: { tool: fs.write, verb: write }
    verdict: allow
""")
    engine = PolicyEngine(policy)

    env = build_envelope(tool="fs.write", verb="write", resource="path:C:/work/out.txt")
    dec = engine.evaluate(env)
    store.record_decision(env, dec)

    # Local execution outcome
    rec_local = store.record_outcome(
        crossing_id=env.crossing_id,
        session_id=env.session_id,
        canonical_hash=env.canonical_hash,
        policy_version=dec.policy_version,
        status="success",
        evidence_status="locally_observed",
    )
    assert rec_local.evidence_status == "locally_observed"
    assert rec_local.to_dict()["evidence_status"] == "locally_observed"

    # Outcome receipt retrieval
    fetched = store.get_outcome_receipt(env.crossing_id)
    assert fetched is not None
    assert fetched.evidence_status == "locally_observed"


def test_durable_session_budgets_across_restarts(tmp_path: Path) -> None:
    db_path = tmp_path / "receipts.db"
    policy_path = tmp_path / "policy.yaml"
    policy_yaml = """
version: 1
defaults: { verdict: deny }
budgets:
  max_actions: 2
  on_exceeded: deny
rules:
  - id: allow-read
    match: { tool: fs.read, verb: read }
    verdict: allow
"""
    policy_path.write_text(policy_yaml, encoding="utf-8")

    # Session 1: Run under first Boundary instance
    b1 = Boundary.from_files(
        policy_path=policy_path,
        receipts_db=db_path,
        session_id="persistent-session-42",
    )

    # Action 1: succeeds
    res1 = b1.execute(
        tool="fs.read", verb="read", resource="path:C:/work/f1.txt", fn=lambda e, d: "ok1"
    )
    assert res1 == "ok1"

    # Action 2: succeeds
    res2 = b1.execute(
        tool="fs.read", verb="read", resource="path:C:/work/f2.txt", fn=lambda e, d: "ok2"
    )
    assert res2 == "ok2"

    # Simulate full process restart: Instantiate completely fresh Boundary on same DB
    b2 = Boundary.from_files(
        policy_path=policy_path,
        receipts_db=db_path,
        session_id="persistent-session-42",
    )

    # Action 3: should be blocked by persisted cumulative session budget!
    with pytest.raises(ActionBlockedError) as exc_info:
        b2.execute(
            tool="fs.read", verb="read", resource="path:C:/work/f3.txt", fn=lambda e, d: "ok3"
        )

    assert exc_info.value.decision.verdict == Verdict.DENY
    assert "budget:max-actions-exceeded" in exc_info.value.decision.rule_id


def test_durable_session_taint_across_restarts(tmp_path: Path) -> None:
    db_path = tmp_path / "receipts.db"
    policy_path = tmp_path / "policy.yaml"
    policy_yaml = """
version: 1
defaults: { verdict: deny }
rules:
  - id: block-tainted-writes
    match: { tool: fs.write, verb: write, taint: untrusted }
    verdict: deny
  - id: allow-untainted-writes
    match: { tool: fs.write, verb: write }
    verdict: allow
"""
    policy_path.write_text(policy_yaml, encoding="utf-8")

    # Instance 1: Mark session as untrusted
    b1 = Boundary.from_files(
        policy_path=policy_path,
        receipts_db=db_path,
        session_id="tainted-session-99",
    )
    b1.set_session_taint("untrusted")
    assert b1.get_session_taint() == "untrusted"

    # Instance 2: Cold restart on same DB
    b2 = Boundary.from_files(
        policy_path=policy_path,
        receipts_db=db_path,
        session_id="tainted-session-99",
    )

    assert b2.get_session_taint() == "untrusted"

    # Action should be evaluated with untrusted taint
    env = build_envelope(
        tool="fs.write",
        verb="write",
        resource="path:C:/work/out.txt",
        session_id="tainted-session-99",
        provenance=[ProvenanceItem(source="session", trust="untrusted")],
    )
    dec = b2.engine.evaluate(env)
    assert dec.verdict == Verdict.DENY
    assert dec.rule_id == "block-tainted-writes"


def test_identity_context_and_principal_validation() -> None:
    # 1. Local trusted caller
    local_ctx = make_local_caller_context()
    assert local_ctx.is_trusted_operator is True
    # Permitted to declare system or trusted
    local_ctx.validate_identity_claims("system", "trusted")

    # 2. Unauthenticated loopback caller
    loopback_ctx = resolve_http_caller_context(
        headers={},
        expected_token="secret-token-123",
        remote_addr="127.0.0.1",
    )
    assert loopback_ctx.is_trusted_operator is False

    # Cannot claim reserved system identity
    with pytest.raises(IdentitySecurityError) as exc:
        loopback_ctx.validate_identity_claims("system")
    assert "cannot claim reserved system identity" in str(exc.value)

    # Cannot assert 'trusted' provenance directly
    with pytest.raises(IdentitySecurityError) as exc2:
        loopback_ctx.validate_identity_claims("normal-agent", claimed_provenance_trust="trusted")
    assert "cannot assert trust='trusted'" in str(exc2.value)

    # Normal agent claim is fine
    loopback_ctx.validate_identity_claims("normal-agent", claimed_provenance_trust="untrusted")


def test_gateway_external_outcome_hardened_with_evidence(tmp_path: Path) -> None:
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml("""
version: 1
defaults: { verdict: deny }
rules:
  - id: allow-calc
    match: { tool: custom.calc }
    verdict: allow
""")
    boundary = Boundary(policy=policy, receipt_store=store)
    services = AppServices(boundary, executor_registry=ExecutorRegistry())

    sub = services.submit_crossing(
        {
            "tool": "custom.calc",
            "verb": "other",
            "resource": "math://add",
            "params": {"a": 1, "b": 2},
        }
    )
    cid = sub["crossing_id"]

    # External caller reports execution outcome
    res = services.record_external_outcome(
        cid, status="success", result_hash="sha256:" + ("b" * 64)
    )
    assert res["status"] == "recorded"
    assert res["reported_by"] == "caller"
    assert res["evidence_tier"] == "caller_reported"
    assert res["externally_verified"] is False

    # Check evidence record was stored
    evs = services.list_evidence(crossing_id=cid)
    assert len(evs) == 1
    assert evs[0]["tier"] == "caller_reported"
    assert evs[0]["trust_domain"] == "external_caller"


def test_canary_propagates_session_taint(tmp_path: Path) -> None:
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    policy_v1 = load_policy_yaml("""
version: 1
defaults: { verdict: deny }
rules:
  - id: allow-fetch
    match: { tool: net.fetch }
    verdict: allow
  - id: allow-write
    match: { tool: fs.write }
    verdict: allow
""")
    boundary = Boundary(policy=policy_v1, receipt_store=store)
    services = AppServices(boundary)

    # Record action 1: untrusted input via gateway services (sets session taint)
    services.submit_crossing(
        {
            "tool": "net.fetch",
            "verb": "read",
            "resource": "http://example.com/api",
            "session_id": "tainted-session-canary",
            "provenance": [{"source": "user", "trust": "untrusted"}],
        }
    )

    # Record action 2 in same session: automatically inherits session taint into stored envelope
    services.submit_crossing(
        {
            "tool": "fs.write",
            "verb": "write",
            "resource": "path:C:/work/out.txt",
            "session_id": "tainted-session-canary",
            "provenance": [],
        }
    )

    # Candidate policy: block write if session is tainted
    candidate_policy = load_policy_yaml(
        """
version: 1
policy_id: candidate-v2
defaults: { verdict: deny }
rules:
  - id: block-tainted-write
    match: { tool: fs.write, verb: write, taint: untrusted }
    verdict: deny
  - id: allow-fetch
    match: { tool: net.fetch }
    verdict: allow
  - id: allow-untainted-write
    match: { tool: fs.write }
    verdict: allow
"""
    )

    summary = run_policy_canary(candidate_policy, db_path)
    # The canary should detect that the write in session 2 is tainted and becomes more restrictive!
    assert summary.more_restrictive_count >= 1
    assert any(d.delta_type == "more_restrictive" for d in summary.diffs)
