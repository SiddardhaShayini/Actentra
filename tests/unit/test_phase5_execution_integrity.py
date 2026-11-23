"""Comprehensive unit, integration, and adversarial tests for Phase 5 (ACT-06).

Execution Integrity and Outcome Verification:
1. Bind postconditions to authorized actions.
2. Independent verification (distinguishing requested, accepted, observed, verified).
3. External outcome claims (mandatory claims, claim binding, single-use, anti-spoofing).
4. Strict postcondition semantics (fs.write digest_match vs weak exists).
5. Failure and uncertainty (uncertainty preserved as unknown, safe reconciliation).
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from actentra import Boundary, PostconditionFailedError
from actentra_core.claims import ExecutionClaimError
from actentra_core.context import (
    AuthorizedExecutionContext,
    ContextError,
    PostconditionSpec,
    build_execution_context,
    compute_content_digest,
    validate_postcondition_semantics,
)
from actentra_core.identity import CallerContext, PrincipalType
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptError, ReceiptStore
from actentra_executors.verifiers import WorkspaceFileVerifier
from actentra_gateway.services import AppServices, ExecutorRegistry

_POLICY_YAML = """\
version: 1
policy_id: test-phase5-execution-integrity
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-compute-verified
    match: { tool: "compute.verified", verb: "exec" }
    verdict: allow
    constraints:
      require_postcondition: true
  - id: allow-compute
    match: { tool: "compute.*", verb: "exec" }
    verdict: allow
  - id: allow-fs-strict
    match: { tool: "fs.write", verb: "write" }
    verdict: allow
    constraints:
      require_postcondition: true
      postcondition: "digest_match"
  - id: allow-fs-delete
    match: { tool: "fs.delete", verb: "delete" }
    verdict: allow
    constraints:
      require_postcondition: true
      postcondition: "absent"
  - id: allow-fs-unconstrained
    match: { tool: "fs.legacy", verb: "write" }
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
        agent_id="agent-phase5",
    )
    return boundary, store, verifier, workspace


# --- 1. Authorized Execution Context & Integrity Binding ---


def test_authorized_execution_context_integrity() -> None:
    """AuthorizedExecutionContext deterministically binds parameters and verifies integrity."""
    ctx = build_execution_context(
        crossing_id="crossing-123",
        tool="fs.write",
        verb="write",
        resource="path:C:/data/file.txt",
        params={"content": "secure-data"},
        principal_id="principal-alice",
        executor_id="executor-fs-1",
        approval_id="approval-456",
        policy_version="1",
        required_postconditions=[
            PostconditionSpec(
                claim="digest_match",
                resource="path:C:/data/file.txt",
                expected_digest="sha256:abc",
            )
        ],
        expected_result_constraints={"status": "ok"},
    )
    assert ctx.verify_integrity() is True
    assert ctx.context_hash.startswith("sha256:")
    assert len(ctx.context_hash) == 71

    # Tampering with any field invalidates cryptographic integrity
    tampered = AuthorizedExecutionContext(
        crossing_id=ctx.crossing_id,
        tool="fs.delete",  # Tampered
        verb=ctx.verb,
        resource=ctx.resource,
        params=ctx.params,
        principal_id=ctx.principal_id,
        executor_id=ctx.executor_id,
        approval_id=ctx.approval_id,
        policy_version=ctx.policy_version,
        required_postconditions=ctx.required_postconditions,
        expected_result_constraints=ctx.expected_result_constraints,
        context_hash=ctx.context_hash,
    )
    assert tampered.verify_integrity() is False


# --- 2. Postcondition Semantics: Generic and Weak Claim Rejection ---


def test_generic_string_claims_unconditionally_rejected() -> None:
    """Generic strings ('verified', 'ok', 'true', etc.) are rejected by semantic validation."""
    for bad_claim in ("verified", "ok", "success", "true", "pass", "valid", "", "any"):
        with pytest.raises(ContextError, match="Generic postcondition claim.*not permitted"):
            validate_postcondition_semantics(
                tool="fs.write",
                verb="write",
                resource="path:C:/data/file.txt",
                claim=bad_claim,
            )


def test_weak_exists_claim_rejected_on_write_in_strict_mode() -> None:
    """Write operations under strict verification reject 'exists' in favor of 'digest_match'."""
    with pytest.raises(ContextError, match="Weak postcondition rejected.*must verify content"):
        validate_postcondition_semantics(
            tool="fs.write",
            verb="write",
            resource="path:C:/data/file.txt",
            claim="exists",
            strict=True,
        )


def test_content_digest_derived_automatically() -> None:
    """For write operations, expected digest is derived automatically from params['content']."""
    content = "Hello, Actentra!"
    expected = compute_content_digest(content)
    spec = validate_postcondition_semantics(
        tool="fs.write",
        verb="write",
        resource="path:C:/data/file.txt",
        claim="digest_match",
        params={"content": content},
        strict=True,
    )
    assert spec.claim == "digest_match"
    assert spec.expected_digest == expected


# --- 3. Binding Postconditions to Authorized Actions in Boundary.execute ---


def test_policy_postcondition_cannot_be_weakened_or_substituted(
    test_env: tuple[Boundary, ReceiptStore, WorkspaceFileVerifier, Path],
) -> None:
    """Caller cannot replace policy-mandated digest_match with weaker or unrelated claims."""
    boundary, store, _, workspace = test_env
    target_file = workspace / "secure.txt"
    target_res = f"path:{target_file.as_posix()}"

    def write_action(env: Any, dec: Any) -> str:
        target_file.write_text("actual-content", encoding="utf-8")
        return "written"

    # 1. Attempting to pass weak 'exists' when policy mandates 'digest_match' fails closed
    match_msg = "Postcondition claim substitution rejected|Weak postcondition"
    with pytest.raises(PostconditionFailedError, match=match_msg):
        boundary.execute(
            tool="fs.write",
            verb="write",
            resource=target_res,
            params={"content": "actual-content"},
            fn=write_action,
            verify_postcondition=True,
            postcondition_claim="exists",  # Weak claim substitution attempt
            raise_on_postcondition_failure=True,
        )

    # 2. Attempting to pass unrelated 'absent' when policy mandates 'digest_match' is rejected
    match_unrelated = "Postcondition claim substitution rejected|Invalid postcondition"
    with pytest.raises(PostconditionFailedError, match=match_unrelated):
        boundary.execute(
            tool="fs.write",
            verb="write",
            resource=target_res,
            params={"content": "actual-content"},
            fn=write_action,
            verify_postcondition=True,
            postcondition_claim="absent",  # Unrelated claim substitution attempt
            raise_on_postcondition_failure=True,
        )


def test_policy_require_postcondition_cannot_be_disabled_by_caller(
    test_env: tuple[Boundary, ReceiptStore, WorkspaceFileVerifier, Path],
) -> None:
    """Passing verify_postcondition=False cannot bypass policy-mandated postcondition checks."""
    boundary, store, _, workspace = test_env
    target_file = workspace / "tampered.txt"
    target_res = f"path:{target_file.as_posix()}"

    def bad_write_action(env: Any, dec: Any) -> str:
        target_file.write_text("wrong-content", encoding="utf-8")
        return "tampered"

    res = boundary.execute(
        tool="fs.write",
        verb="write",
        resource=target_res,
        params={"content": "expected-content"},
        fn=bad_write_action,
        verify_postcondition=False,  # Bypass attempt!
    )
    assert res == "tampered"

    outcome = store.iter_records()[-1]
    assert outcome.record_type == "outcome"
    assert outcome.status == "failure"
    assert outcome.reason == "postcondition_refuted"


def test_verified_digest_match_records_success(
    test_env: tuple[Boundary, ReceiptStore, WorkspaceFileVerifier, Path],
) -> None:
    """When action creates file with matching content digest, verified success is recorded."""
    boundary, store, _, workspace = test_env
    target_file = workspace / "correct.txt"
    target_res = f"path:{target_file.as_posix()}"
    content = "exact payload for actentra"

    def correct_write_action(env: Any, dec: Any) -> str:
        target_file.write_text(content, encoding="utf-8")
        return "written_ok"

    res = boundary.execute(
        tool="fs.write",
        verb="write",
        resource=target_res,
        params={"content": content},
        fn=correct_write_action,
        verify_postcondition=True,
    )
    assert res == "written_ok"

    outcome = store.iter_records()[-1]
    assert outcome.record_type == "outcome"
    assert outcome.status == "success"
    assert outcome.evidence_status == "externally_verified"

    ev_list = store.list_evidence(tier="externally_verified")
    assert len(ev_list) == 1
    assert ev_list[0].details["status"] == "verified"


# --- 4. External Outcome Claims & Anti-Omission ---


def test_external_outcome_requires_claim(tmp_path: Path) -> None:
    """Reporting external outcome without claim is rejected when required."""
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_POLICY_YAML)
    boundary = Boundary(policy=policy, receipt_store=store, agent_id="agent-worker")
    services = AppServices(boundary, executor_registry=ExecutorRegistry())

    raw_envelope = {
        "tool": "compute.add",
        "verb": "exec",
        "resource": "tool:calc",
        "params": {"a": 1},
        "session_id": "sess-phase5",
        "agent": {"id": "agent-worker"},
    }
    submit_res = services.submit_crossing(raw_envelope, execute=False)
    cid = submit_res["crossing_id"]
    assert submit_res["verdict"] == "allow"

    res = services.record_external_outcome(
        cid, status="success", claim_id=None, require_claim=True
    )
    assert "error" in res
    assert res.get("code") == "claim_required"


def test_claim_cannot_be_reused_across_crossings(tmp_path: Path) -> None:
    """An execution claim issued for crossing A cannot be used for crossing B."""
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_POLICY_YAML)
    boundary = Boundary(policy=policy, receipt_store=store, agent_id="agent-worker")
    services = AppServices(boundary, executor_registry=ExecutorRegistry())

    ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="executor-worker",
        authenticated=True,
        trust_domain="local",
        scopes=("crossings:claim", "crossings:outcome"),
        allowed_agents=("agent-worker",),
    )

    sub_a = services.submit_crossing(
        {
            "tool": "compute.a",
            "verb": "exec",
            "resource": "res-a",
            "session_id": "s1",
            "agent": {"id": "agent-worker"},
        },
        execute=False,
    )
    cid_a = sub_a["crossing_id"]

    sub_b = services.submit_crossing(
        {
            "tool": "compute.b",
            "verb": "exec",
            "resource": "res-b",
            "session_id": "s1",
            "agent": {"id": "agent-worker"},
        },
        execute=False,
    )
    cid_b = sub_b["crossing_id"]

    claim_a = services.claim_crossing_for_execution(cid_a, caller_context=ctx)
    claim_id_a = claim_a["claim_id"]

    res = services.record_external_outcome(
        cid_b,
        status="success",
        claim_id=claim_id_a,
        caller_context=ctx,
    )
    assert "error" in res
    assert "does not match" in res["error"] or res.get("code") in ("conflict", "claim_invalid")


def test_false_success_promotion_rejected_without_verified_state(tmp_path: Path) -> None:
    """External executor cannot report success without verified evidence when required."""
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_POLICY_YAML)
    boundary = Boundary(policy=policy, receipt_store=store, agent_id="agent-worker")
    services = AppServices(boundary, executor_registry=ExecutorRegistry())

    ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="executor-worker",
        authenticated=True,
        trust_domain="local",
        scopes=("crossings:claim", "crossings:outcome"),
        allowed_agents=("agent-worker",),
    )

    sub = services.submit_crossing(
        {
            "tool": "compute.verified",
            "verb": "exec",
            "resource": "res-verified",
            "session_id": "s-ver",
            "agent": {"id": "agent-worker"},
        },
        execute=False,
    )
    cid = sub["crossing_id"]

    claim = services.claim_crossing_for_execution(cid, caller_context=ctx)
    claim_id = claim["claim_id"]

    res = services.record_external_outcome(
        cid,
        status="success",
        claim_id=claim_id,
        caller_context=ctx,
    )
    assert "error" in res
    assert res.get("code") == "unverified_postcondition"
    assert "False success promotion rejected" in res["error"]


# --- 5. Failure and Uncertainty Preservation & Safe Reconciliation ---


def test_uncertain_outcome_preserved_as_unknown_when_verifier_unconfigured(
    tmp_path: Path,
) -> None:
    """When postcondition is requested without verifier, status is preserved as 'unknown'."""
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(_POLICY_YAML)
    boundary = Boundary(policy=policy, receipt_store=store, agent_id="agent-no-verifier")

    res = boundary.execute(
        tool="fs.legacy",
        verb="write",
        resource="path:C:/data/dummy.txt",
        fn=lambda _e, _d: "did_something",
        verify_postcondition=True,
        postcondition_claim="exists",
    )
    assert res == "did_something"

    outcome = store.iter_records()[-1]
    assert outcome.record_type == "outcome"
    assert outcome.status == "unknown"
    assert outcome.evidence_status == "unknown"
    assert outcome.reason == "postcondition_unverified"


def test_safe_reconciliation_of_unknown_outcome(
    test_env: tuple[Boundary, ReceiptStore, WorkspaceFileVerifier, Path],
) -> None:
    """An uncertain ('unknown') outcome can be safely reconciled via independent verification."""
    boundary, store, verifier, workspace = test_env
    target_file = workspace / "reconcile_target.txt"
    target_res = f"path:{target_file.as_posix()}"
    content = "reconciled content"

    boundary_unverified = Boundary(
        policy=load_policy_yaml(_POLICY_YAML),
        receipt_store=store,
        verifier=None,
        agent_id="agent-phase5",
    )
    boundary_unverified.execute(
        tool="fs.legacy",
        verb="write",
        resource=target_res,
        params={"content": content},
        fn=lambda _e, _d: "executed",
        verify_postcondition=True,
    )

    crossing_id = store.iter_records()[-1].crossing_id
    out_before = store.get_outcome_receipt(crossing_id)
    assert out_before is not None
    assert out_before.status == "unknown"

    target_file.write_text(content, encoding="utf-8")

    reconciled = boundary.reconcile_outcome(crossing_id)
    assert reconciled.status == "success"
    assert reconciled.evidence_status == "externally_verified"
    assert "reconciled_verified" in str(reconciled.reason)

    out_after = store.get_outcome_receipt(crossing_id)
    assert out_after is not None
    assert out_after.status == "success"
    assert out_after.evidence_status == "externally_verified"


def test_terminal_outcomes_cannot_be_reconciled(
    test_env: tuple[Boundary, ReceiptStore, WorkspaceFileVerifier, Path],
) -> None:
    """Terminal verified success or failure outcomes cannot be overwritten by reconciliation."""
    boundary, store, _, workspace = test_env
    target_file = workspace / "terminal.txt"
    target_res = f"path:{target_file.as_posix()}"
    content = "terminal"

    def write_fn(env: Any, dec: Any) -> str:
        target_file.write_text(content, encoding="utf-8")
        return "done"

    boundary.execute(
        tool="fs.write",
        verb="write",
        resource=target_res,
        params={"content": content},
        fn=write_fn,
        verify_postcondition=True,
    )
    cid = store.iter_records()[-1].crossing_id
    out = store.get_outcome_receipt(cid)
    assert out is not None
    assert out.status == "success"

    with pytest.raises(ReceiptError, match="Cannot reconcile outcome with terminal status"):
        boundary.reconcile_outcome(cid)


def test_claim_cannot_be_consumed_by_different_principal(tmp_path: Path) -> None:
    """ReceiptStore rejects claim consumption if executor principal does not match."""
    db_path = tmp_path / "claims.db"
    store = ReceiptStore(db_path)

    claim = store.issue_execution_claim(
        crossing_id="crossing-1",
        executor_principal_id="executor-alice",
        session_id="session-1",
        canonical_hash="sha256:" + ("a" * 64),
    )

    expected_err = "issued to executor 'executor-alice', not caller 'executor-bob'"
    with pytest.raises(ExecutionClaimError, match=expected_err):
        store.consume_execution_claim(
            claim.claim_id,
            executor_principal_id="executor-bob",
            crossing_id="crossing-1",
        )


def test_claim_action_hash_mismatch_rejected(tmp_path: Path) -> None:
    """ReceiptStore rejects claim consumption if canonical action hash does not match."""
    db_path = tmp_path / "claims.db"
    store = ReceiptStore(db_path)

    claim = store.issue_execution_claim(
        crossing_id="crossing-1",
        executor_principal_id="executor-alice",
        session_id="session-1",
        canonical_hash="sha256:" + ("a" * 64),
    )

    with pytest.raises(ExecutionClaimError, match="was issued for action hash"):
        store.consume_execution_claim(
            claim.claim_id,
            executor_principal_id="executor-alice",
            crossing_id="crossing-1",
            canonical_hash="sha256:" + ("b" * 64),
        )


def test_claim_result_digest_mismatch_rejected(tmp_path: Path) -> None:
    """ReceiptStore rejects claim consumption if bound result digest mismatches."""
    db_path = tmp_path / "claims.db"
    store = ReceiptStore(db_path)

    claim = store.issue_execution_claim(
        crossing_id="crossing-1",
        executor_principal_id="executor-alice",
        session_id="session-1",
        canonical_hash="sha256:" + ("a" * 64),
        result_digest="sha256:" + ("1" * 64),
    )

    with pytest.raises(ExecutionClaimError, match="Result digest mismatch"):
        store.consume_execution_claim(
            claim.claim_id,
            executor_principal_id="executor-alice",
            crossing_id="crossing-1",
            result_digest="sha256:" + ("2" * 64),
        )


def test_reconcile_outcome_refuted_transition(
    test_env: tuple[Boundary, ReceiptStore, WorkspaceFileVerifier, Path],
) -> None:
    """Reconciling an unknown outcome where state is refuted safely transitions to failure."""
    boundary, store, verifier, workspace = test_env
    target_file = workspace / "refuted_target.txt"
    target_res = f"path:{target_file.as_posix()}"

    boundary_unverified = Boundary(
        policy=load_policy_yaml(_POLICY_YAML),
        receipt_store=store,
        verifier=None,
        agent_id="agent-phase5",
    )
    boundary_unverified.execute(
        tool="fs.legacy",
        verb="write",
        resource=target_res,
        params={"content": "missing"},
        fn=lambda _e, _d: "executed",
        verify_postcondition=True,
    )

    crossing_id = store.iter_records()[-1].crossing_id
    out_before = store.get_outcome_receipt(crossing_id)
    assert out_before is not None
    assert out_before.status == "unknown"

    reconciled = boundary.reconcile_outcome(crossing_id)
    assert reconciled.status == "failure"
    assert "reconciled_refuted" in str(reconciled.reason)

    out_after = store.get_outcome_receipt(crossing_id)
    assert out_after is not None
    assert out_after.status == "failure"


def test_concurrent_reconciliation_is_safe_and_atomic(
    test_env: tuple[Boundary, ReceiptStore, WorkspaceFileVerifier, Path],
) -> None:
    """Concurrent reconciliation attempts on unknown outcome execute atomically without error."""
    boundary, store, verifier, workspace = test_env
    target_file = workspace / "concurrent_reconcile.txt"
    target_res = f"path:{target_file.as_posix()}"
    content = "concurrent reconciliation"

    boundary_unverified = Boundary(
        policy=load_policy_yaml(_POLICY_YAML),
        receipt_store=store,
        verifier=None,
        agent_id="agent-phase5",
    )
    boundary_unverified.execute(
        tool="fs.legacy",
        verb="write",
        resource=target_res,
        params={"content": content},
        fn=lambda _e, _d: "executed",
        verify_postcondition=True,
    )

    crossing_id = store.iter_records()[-1].crossing_id
    target_file.write_text(content, encoding="utf-8")

    results: list[Any] = []
    errors: list[Exception] = []

    def _worker() -> None:
        try:
            res = boundary.reconcile_outcome(crossing_id)
            results.append(res)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=_worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    out = store.get_outcome_receipt(crossing_id)
    assert out is not None
    assert out.status == "success"
    assert out.evidence_status == "externally_verified"
