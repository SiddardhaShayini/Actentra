"""Security regression tests for Finding 04: Postcondition verification and outcome finalization.

Verifies:
- Outcome is finalized strictly AFTER postcondition verification (no premature success receipts).
- Claim 'exists': verified -> success (externally_verified); refuted -> failure (locally_observed).
- Claim 'absent': verified -> success; refuted -> failure.
- Claim 'digest_match': verified -> success; refuted -> failure.
- Verifier 'error' / invalid query -> unknown outcome, no externally_verified evidence.
- Verifier exception -> caught cleanly, recorded as unknown outcome, observation logged as error.
- Stale observation -> unknown outcome, stale evidence_status.
- Unconfigured verifier with verify_postcondition=True -> unknown outcome.
- Atomic binding: observation and outcome committed in one SQLite transaction.
- raise_on_postcondition_failure flag strictly raises PostconditionFailedError when requested.
- Externally-verified EvidenceRecords and CausalLinks are NEVER emitted on non-success outcomes.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from actentra import Boundary, PostconditionFailedError
from actentra_core.evidence import EvidenceTier
from actentra_core.observations import build_observation
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_executors.verifiers import WorkspaceFileVerifier

_POLICY_YAML = """\
version: 1
policy_id: test-postconditions
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-fs
    match: { tool: "fs.*", verb: "write" }
    verdict: allow
  - id: allow-exec
    match: { tool: "exec.*", verb: "exec" }
    verdict: allow
"""


@pytest.fixture
def test_env(tmp_path: Path) -> tuple[Boundary, ReceiptStore, WorkspaceFileVerifier, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    verifier = WorkspaceFileVerifier(workspace)
    policy = load_policy_yaml(_POLICY_YAML)
    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        verifier=verifier,
        agent_id="agent-writer",
    )
    return boundary, store, verifier, workspace


def test_postcondition_exists_verified_records_success(
    test_env: tuple[Boundary, ReceiptStore, WorkspaceFileVerifier, Path],
) -> None:
    """Exists claim succeeds when file was created; records success & externally_verified."""
    boundary, store, _, workspace = test_env
    target_file = workspace / "created.txt"
    target_res = f"path:{target_file.as_posix()}"

    def write_action(env: Any, dec: Any) -> str:
        target_file.write_text("hello world", encoding="utf-8")
        return "written"

    res = boundary.execute(
        tool="fs.write",
        verb="write",
        resource=target_res,
        fn=write_action,
        verify_postcondition=True,
        postcondition_claim="exists",
    )
    assert res == "written"

    # Outcome receipt must be success with externally_verified evidence
    receipts = store.iter_records()
    outcome = next(r for r in receipts if r.record_type == "outcome")
    assert outcome.status == "success"
    assert outcome.evidence_status == "externally_verified"

    # Observation persisted
    obs_list = store.list_observations()
    assert len(obs_list) == 1
    assert obs_list[0].status == "verified"
    assert obs_list[0].claim == "exists"

    # Externally verified EvidenceRecord and causal DAG link created
    ev_list = store.list_evidence(tier="externally_verified")
    assert len(ev_list) == 1
    assert ev_list[0].tier == EvidenceTier.EXTERNALLY_VERIFIED
    links = store.list_causal_links()
    assert len(links) == 1
    assert links[0].relation == "verifies"


def test_postcondition_exists_refuted_records_failure_and_no_external_evidence(
    test_env: tuple[Boundary, ReceiptStore, WorkspaceFileVerifier, Path],
) -> None:
    """T-04: Exists claim fails when file is absent; records failure, NOT success."""
    boundary, store, _, workspace = test_env
    target_file = workspace / "missing.txt"
    target_res = f"path:{target_file.as_posix()}"

    def failed_write_action(env: Any, dec: Any) -> str:
        # Action ran and returned, but failed to create the target file
        return "claimed_written"

    res = boundary.execute(
        tool="fs.write",
        verb="write",
        resource=target_res,
        fn=failed_write_action,
        verify_postcondition=True,
        postcondition_claim="exists",
    )
    assert res == "claimed_written"

    # Outcome receipt MUST be failure (NOT success!)
    receipts = store.iter_records()
    outcome = next(r for r in receipts if r.record_type == "outcome")
    assert outcome.status == "failure"
    assert outcome.evidence_status == "locally_observed"
    assert outcome.reason == "postcondition_refuted"
    assert "refuted" in (outcome.error or "")

    # Observation recorded as refuted
    obs_list = store.list_observations()
    assert len(obs_list) == 1
    assert obs_list[0].status == "refuted"

    # CRITICAL: No externally_verified evidence record or verifies link emitted
    ev_list = store.list_evidence(tier="externally_verified")
    assert len(ev_list) == 0
    links = store.list_causal_links()
    assert len(links) == 0


def test_postcondition_absent_claim_semantics(
    test_env: tuple[Boundary, ReceiptStore, WorkspaceFileVerifier, Path],
) -> None:
    """T-04: Absent claim verified when file missing, refuted when file exists."""
    boundary, store, _, workspace = test_env
    target_file = workspace / "to_delete.txt"
    target_res = f"path:{target_file.as_posix()}"

    # Scenario A: Delete action actually removes the file -> verified
    target_file.write_text("temp", encoding="utf-8")

    def successful_delete(env: Any, dec: Any) -> str:
        target_file.unlink()
        return "deleted"

    res1 = boundary.execute(
        tool="fs.write",
        verb="write",
        resource=target_res,
        fn=successful_delete,
        verify_postcondition=True,
        postcondition_claim="absent",
    )
    assert res1 == "deleted"
    out1 = store.get_outcome_receipt(store.iter_records()[-1].crossing_id)
    assert out1 is not None
    assert out1.status == "success"
    assert out1.evidence_status == "externally_verified"

    # Scenario B: Delete action fails to remove the file -> refuted
    target_file.write_text("still_here", encoding="utf-8")

    def failed_delete(env: Any, dec: Any) -> str:
        return "pretend_deleted"

    res2 = boundary.execute(
        tool="fs.write",
        verb="write",
        resource=target_res,
        fn=failed_delete,
        verify_postcondition=True,
        postcondition_claim="absent",
    )
    assert res2 == "pretend_deleted"
    out2 = store.get_outcome_receipt(store.iter_records()[-1].crossing_id)
    assert out2 is not None
    assert out2.status == "failure"
    assert out2.reason == "postcondition_refuted"


def test_postcondition_digest_match_claim_semantics(
    test_env: tuple[Boundary, ReceiptStore, WorkspaceFileVerifier, Path],
) -> None:
    """T-04: Digest_match verified when hash matches, refuted when hash deviates."""
    boundary, store, _, workspace = test_env
    target_file = workspace / "data.bin"
    target_res = f"path:{target_file.as_posix()}"

    content = b"exact cryptographic content"
    correct_digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
    wrong_digest = "sha256:" + ("0" * 64)

    # 1. Matching digest -> verified success
    def write_exact(env: Any, dec: Any) -> None:
        target_file.write_bytes(content)

    boundary.execute(
        tool="fs.write",
        verb="write",
        resource=target_res,
        fn=write_exact,
        verify_postcondition=True,
        postcondition_claim="digest_match",
        postcondition_expected_digest=correct_digest,
    )
    out1 = store.get_outcome_receipt(store.iter_records()[-1].crossing_id)
    assert out1 is not None
    assert out1.status == "success"
    assert out1.evidence_status == "externally_verified"

    # 2. Deviating digest -> refuted failure
    boundary.execute(
        tool="fs.write",
        verb="write",
        resource=target_res,
        fn=lambda env, dec: None,
        verify_postcondition=True,
        postcondition_claim="digest_match",
        postcondition_expected_digest=wrong_digest,
    )
    out2 = store.get_outcome_receipt(store.iter_records()[-1].crossing_id)
    assert out2 is not None
    assert out2.status == "failure"
    assert out2.reason == "postcondition_refuted"


def test_postcondition_verifier_error_records_unknown(
    test_env: tuple[Boundary, ReceiptStore, WorkspaceFileVerifier, Path],
) -> None:
    """T-04: Verifier error (e.g. missing digest param) maps to unknown outcome."""
    boundary, store, _, workspace = test_env
    target_file = workspace / "file.txt"
    target_file.write_text("data")
    target_res = f"path:{target_file.as_posix()}"

    # digest_match without postcondition_expected_digest triggers verifier error
    boundary.execute(
        tool="fs.write",
        verb="write",
        resource=target_res,
        fn=lambda env, dec: "ok",
        verify_postcondition=True,
        postcondition_claim="digest_match",
        postcondition_expected_digest=None,
    )
    out = store.get_outcome_receipt(store.iter_records()[-1].crossing_id)
    assert out is not None
    assert out.status == "unknown"
    assert out.evidence_status == "unknown"
    assert out.reason == "postcondition_error"


def test_postcondition_verifier_exception_records_unknown(
    tmp_path: Path,
) -> None:
    """T-04: Verifier raising an unhandled exception maps cleanly to unknown outcome."""
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_POLICY_YAML)

    class CrashingVerifier:
        verifier_id = "actentra.verifier.crash"
        verifier_version = "1.0.0"

        def verify(self, resource: str, claim: str, **kwargs: Any) -> Any:
            raise OSError("Hardware I/O bus failure")

    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        verifier=CrashingVerifier(),
        agent_id="agent-writer",
    )

    boundary.execute(
        tool="exec.run",
        verb="exec",
        resource="tool:run",
        fn=lambda env, dec: "finished",
        verify_postcondition=True,
        postcondition_claim="exists",
    )

    out = store.get_outcome_receipt(store.iter_records()[-1].crossing_id)
    assert out is not None
    assert out.status == "unknown"
    assert out.evidence_status == "unknown"
    assert "Hardware I/O bus failure" in (out.error or "")

    # Observation recorded as error
    obs_list = store.list_observations()
    assert len(obs_list) == 1
    assert obs_list[0].status == "error"
    assert "Hardware I/O bus failure" in (obs_list[0].error or "")


def test_postcondition_stale_observation_records_unknown(
    tmp_path: Path,
) -> None:
    """T-04: Verifier returning a stale observation maps to unknown outcome."""
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_POLICY_YAML)

    class StaleVerifier:
        verifier_id = "actentra.verifier.stale"
        verifier_version = "1.0.0"

        def verify(self, resource: str, claim: str, **kwargs: Any) -> Any:
            return build_observation(
                subject_resource=resource,
                claim=claim,
                status="stale",
                verifier_id=self.verifier_id,
                error="Observation timestamp expired",
            )

    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        verifier=StaleVerifier(),
        agent_id="agent-writer",
    )

    boundary.execute(
        tool="exec.run",
        verb="exec",
        resource="tool:run",
        fn=lambda env, dec: "done",
        verify_postcondition=True,
        postcondition_claim="exists",
    )

    out = store.get_outcome_receipt(store.iter_records()[-1].crossing_id)
    assert out is not None
    assert out.status == "unknown"
    assert out.evidence_status == "stale"
    assert out.reason == "postcondition_stale"


def test_postcondition_unconfigured_verifier_records_unknown(
    tmp_path: Path,
) -> None:
    """Verify_postcondition=True without a configured verifier yields unknown outcome."""
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_POLICY_YAML)

    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        verifier=None,  # No verifier
        agent_id="agent-writer",
    )

    boundary.execute(
        tool="exec.run",
        verb="exec",
        resource="tool:run",
        fn=lambda env, dec: "done",
        verify_postcondition=True,
    )

    out = store.get_outcome_receipt(store.iter_records()[-1].crossing_id)
    assert out is not None
    assert out.status == "unknown"
    assert out.reason == "postcondition_unverified"
    assert "no verifier is configured" in (out.error or "")


def test_raise_on_postcondition_failure_strictly_enforces_contract(
    test_env: tuple[Boundary, ReceiptStore, WorkspaceFileVerifier, Path],
) -> None:
    """When raise_on_postcondition_failure=True, refuted or error postconditions raise."""
    boundary, store, _, workspace = test_env
    target_file = workspace / "uncreated.txt"
    target_res = f"path:{target_file.as_posix()}"

    # 1. Refuted raises PostconditionFailedError with outcome_status="failure"
    with pytest.raises(PostconditionFailedError) as exc_info:
        boundary.execute(
            tool="fs.write",
            verb="write",
            resource=target_res,
            fn=lambda env, dec: "noop",
            verify_postcondition=True,
            postcondition_claim="exists",
            raise_on_postcondition_failure=True,
        )
    assert exc_info.value.outcome_status == "failure"
    assert "refuted" in str(exc_info.value)
    assert exc_info.value.observation is not None
    assert exc_info.value.observation.status == "refuted"

    # Outcome receipt was still persisted as failure
    out = store.get_outcome_receipt(store.iter_records()[-1].crossing_id)
    assert out is not None
    assert out.status == "failure"


def test_atomic_observation_and_outcome_transaction(tmp_path: Path) -> None:
    """ReceiptStore.record_outcome with observation commits atomically."""
    db_path = tmp_path / "atomic.db"
    store = ReceiptStore(db_path)

    obs = build_observation(
        subject_resource="path:C:/data/config.json",
        claim="exists",
        status="verified",
        verifier_id="actentra.verifier.fs.v1",
        crossing_id="cross_12345",
    )

    # Record outcome with atomic observation parameter
    receipt = store.record_outcome(
        crossing_id="cross_12345",
        session_id="sess_abc",
        canonical_hash="sha256:" + ("0" * 64),
        policy_version="1.0",
        status="success",
        evidence_status="externally_verified",
        observation=obs,
    )
    assert receipt.status == "success"

    # Both tables now have the records committed
    stored_obs = store.get_observation(obs.observation_id)
    assert stored_obs is not None
    assert stored_obs.observation_id == obs.observation_id
    assert stored_obs.status == "verified"

    stored_outcome = store.get_outcome_receipt("cross_12345")
    assert stored_outcome is not None
    assert stored_outcome.status == "success"
    assert stored_outcome.evidence_status == "externally_verified"
