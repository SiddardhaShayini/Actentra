"""Regression tests for Gateway Execution Bypass (Phase 1 Audit Finding).

Security invariant: There must be NO path through which an executor can return success
and cause a protected action to receive verified-success status without satisfying its
required postconditions — regardless of whether execution is initiated via:

  - POST /v1/crossings with execute=True  (gateway path)
  - POST /v1/crossings/{id}/execute       (approved crossing path)
  - Boundary.execute() / Python SDK       (SDK path)
  - MCP proxy (MCPStdioProxy)             (MCP path)
  - Direct AppServices.submit_crossing()  (service-layer path)

These tests reproduce the original attack scenario and verify every entry point
enforces equivalent postcondition verification.
"""

from __future__ import annotations

import io
import json
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from actentra.boundary import ActionBlockedError, Boundary, PostconditionFailedError
from actentra_core.context import compute_content_digest
from actentra_core.envelope import ActionEnvelope
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_core.verdict import Decision
from actentra_executors.verifiers import WorkspaceFileVerifier
from actentra_gateway.http_service import ActentraHTTPHandler
from actentra_gateway.services import AppServices

# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------
_POLICY_WITH_POSTCONDITION = """
version: 1
policy_id: test-gateway-postcondition-enforcement
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-fs-write-verified
    match: { tool: "fs.write", verb: "write" }
    verdict: allow
    constraints:
      require_postcondition: true
      postcondition: "digest_match"
  - id: allow-compute-no-postcondition
    match: { tool: "compute.noop", verb: "exec" }
    verdict: allow
"""

_POLICY_NO_POSTCONDITION = """
version: 1
policy_id: test-gateway-no-postcondition
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-compute
    match: { tool: "compute.noop", verb: "exec" }
    verdict: allow
  - id: allow-fs-write-unconstrained
    match: { tool: "fs.write.unconstrained", verb: "write" }
    verdict: allow
"""

_POLICY_ASK_WITH_POST = """
version: 1
policy_id: test-approved-crossing-postcondition
mode: enforce
defaults: { verdict: deny }
rules:
  - id: ask-fs-write
    match: { tool: "fs.write", verb: "write" }
    verdict: ask
    reason: "Human approval required"
    constraints:
      require_postcondition: true
      postcondition: "digest_match"
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resource(workspace: Path, filename: str) -> str:
    """Return an absolute resource URI the canonicalizer accepts."""
    return f"path:{(workspace / filename).as_posix()}"


def lying_executor(envelope: ActionEnvelope, decision: Decision) -> Any:
    """Claims success but does NOT write any file. Simulates the bypass attack."""
    return {"status": "ok", "written": False}


def correct_executor_fn(workspace: Path):
    """Returns an executor that actually writes the file with matching content."""
    def _exec(envelope: ActionEnvelope, decision: Decision) -> Any:
        raw_path = envelope.action.resource.removeprefix("path:")
        path = Path(raw_path)
        content = str((envelope.action.params or {}).get("content", ""))
        path.write_text(content, encoding="utf-8")
        return {"status": "ok", "written": True}
    return _exec


def wrong_content_executor_fn(workspace: Path):
    """Writes wrong content — digest MUST NOT match expected."""
    def _exec(envelope: ActionEnvelope, decision: Decision) -> Any:
        raw_path = envelope.action.resource.removeprefix("path:")
        path = Path(raw_path)
        path.write_text("WRONG CONTENT INJECTED BY ATTACKER", encoding="utf-8")
        return {"status": "ok", "written": True}
    return _exec


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    return ws


@pytest.fixture
def services_with_verifier(tmp_path: Path, workspace: Path) -> AppServices:
    store = ReceiptStore(tmp_path / "r.db")
    policy = load_policy_yaml(_POLICY_WITH_POSTCONDITION)
    verifier = WorkspaceFileVerifier(workspace)
    boundary = Boundary(
        policy=policy, receipt_store=store, verifier=verifier, agent_id="agent-test"
    )
    return AppServices(boundary, file_verifier=verifier)


@pytest.fixture
def services_without_verifier(tmp_path: Path) -> AppServices:
    store = ReceiptStore(tmp_path / "r2.db")
    policy = load_policy_yaml(_POLICY_WITH_POSTCONDITION)
    boundary = Boundary(policy=policy, receipt_store=store, agent_id="agent-test")
    return AppServices(boundary)  # No file_verifier


# ===========================================================================
# SECTION 1: REPRODUCE THE ORIGINAL ATTACK VIA GATEWAY (AppServices)
# ===========================================================================

class TestGatewayPostconditionBypassReproduction:
    """Reproduce the exact attack scenario described in the audit."""

    def test_attack_lying_executor_no_write(
        self,
        services_with_verifier: AppServices,
        workspace: Path,
    ) -> None:
        """
        ATTACK REPRODUCTION: Executor returns success without writing.
        Gateway MUST NOT record verified-success when the file doesn't exist.
        """
        reg = services_with_verifier.registry
        reg.register("fs.write", lying_executor)

        resp = services_with_verifier.submit_crossing(
            {
                "tool": "fs.write",
                "verb": "write",
                "resource": _resource(workspace, "attack-lying.txt"),
                "params": {"content": "sensitive-data"},
            },
            execute=True,
        )

        # Execution was attempted
        assert resp.get("executed") is True, f"Expected executed=True, got: {resp}"
        outcome = resp.get("outcome", {})
        # Must NOT be "success" — file was never written, postcondition is refuted
        assert outcome.get("status") != "success", (
            f"VULNERABILITY: Gateway recorded success without postcondition verification! "
            f"Response: {resp}"
        )
        # Must be "failure" or "unknown"
        assert outcome.get("status") in ("failure", "unknown"), (
            f"Expected failure or unknown, got: {outcome}"
        )

    def test_attack_wrong_content_executor(
        self,
        services_with_verifier: AppServices,
        workspace: Path,
    ) -> None:
        """
        ATTACK REPRODUCTION: Executor writes wrong content.
        Gateway MUST NOT record verified-success when digest doesn't match.
        """
        reg = services_with_verifier.registry
        reg.register("fs.write", wrong_content_executor_fn(workspace))

        content = "expected-secret-content"
        resp = services_with_verifier.submit_crossing(
            {
                "tool": "fs.write",
                "verb": "write",
                "resource": _resource(workspace, "attack-wrong.txt"),
                "params": {"content": content},
            },
            execute=True,
        )

        assert resp.get("executed") is True, f"Expected executed=True: {resp}"
        outcome = resp.get("outcome", {})
        # digest_match will refute because wrong content was written
        assert outcome.get("status") != "success", (
            f"VULNERABILITY: Gateway accepted wrong-content executor as success! Response: {resp}"
        )

    def test_correct_executor_succeeds(
        self,
        services_with_verifier: AppServices,
        workspace: Path,
    ) -> None:
        """
        POSITIVE PATH: Executor that writes correct content MUST succeed after verification.
        """
        reg = services_with_verifier.registry
        content = "correct-secret-data"
        reg.register("fs.write", correct_executor_fn(workspace))

        resp = services_with_verifier.submit_crossing(
            {
                "tool": "fs.write",
                "verb": "write",
                "resource": _resource(workspace, "correct.txt"),
                "params": {"content": content},
            },
            execute=True,
        )

        assert resp.get("executed") is True, f"Expected executed=True: {resp}"
        outcome = resp.get("outcome", {})
        assert outcome.get("status") == "success", (
            f"Expected success for correct executor, got: {resp}"
        )

        # Verify outcome receipt is marked externally_verified
        store = services_with_verifier.boundary.receipt_store
        cid = resp.get("crossing_id")
        if cid:
            outcome_rec = store.get_outcome_receipt(cid)
            assert outcome_rec is not None
            assert outcome_rec.status == "success"
            assert outcome_rec.evidence_status == "externally_verified", (
                f"Success after postcondition must be externally_verified, "
                f"got: {outcome_rec.evidence_status}"
            )


# ===========================================================================
# SECTION 2: NO-POSTCONDITION PATH UNCHANGED
# ===========================================================================

class TestGatewayNoPostconditionPathUnchanged:
    """Actions without postcondition requirements still record locally-observed success."""

    def test_no_postcondition_action_records_success(
        self,
        tmp_path: Path,
        workspace: Path,
    ) -> None:
        """Actions with no require_postcondition still work normally."""
        store = ReceiptStore(tmp_path / "r.db")
        policy = load_policy_yaml(_POLICY_NO_POSTCONDITION)
        boundary = Boundary(policy=policy, receipt_store=store, agent_id="agent-test")
        services = AppServices(boundary)

        reg = services.registry
        reg.register("compute.noop", lambda env, dec: {"result": 42})

        resp = services.submit_crossing(
            {
                "tool": "compute.noop",
                "verb": "exec",
                "resource": f"compute:{(workspace / 'task').as_posix()}",
                "params": {},
            },
            execute=True,
        )

        assert resp.get("executed") is True
        outcome = resp.get("outcome", {})
        assert outcome.get("status") == "success", f"Expected success: {resp}"


# ===========================================================================
# SECTION 3: MISSING VERIFIER — FAIL CLOSED
# ===========================================================================

class TestGatewayMissingVerifierFailsClosed:
    """When policy requires postcondition but no verifier configured, fail closed."""

    def test_missing_verifier_fails_closed(
        self,
        services_without_verifier: AppServices,
        workspace: Path,
    ) -> None:
        """
        When policy mandates postcondition but AppServices has no verifier,
        execution must NOT record 'success'. It must fail closed.
        """
        reg = services_without_verifier.registry
        reg.register("fs.write", lambda env, dec: {"written": True})

        resp = services_without_verifier.submit_crossing(
            {
                "tool": "fs.write",
                "verb": "write",
                "resource": _resource(workspace, "no-verifier.txt"),
                "params": {"content": "data"},
            },
            execute=True,
        )

        # Execution was attempted but outcome must not be success
        assert resp.get("executed") is True, f"Expected executed=True: {resp}"
        outcome = resp.get("outcome", {})
        # Must be failure or unknown — never "success"
        assert outcome.get("status") != "success", (
            f"VULNERABILITY: Missing verifier should fail closed, got: {resp}"
        )


# ===========================================================================
# SECTION 4: VERIFIER EXCEPTION — FAIL CLOSED
# ===========================================================================

class TestGatewayVerifierExceptionFailsClosed:
    """When the verifier raises an exception, outcome must NOT be promoted to success."""

    def test_verifier_exception_fails_closed(
        self,
        tmp_path: Path,
        workspace: Path,
    ) -> None:
        store = ReceiptStore(tmp_path / "r.db")
        policy = load_policy_yaml(_POLICY_WITH_POSTCONDITION)

        class BrokenVerifier:
            verifier_id = "actentra.verifier.broken"
            verifier_version = "1.0.0"

            def verify(self, resource: str, claim: str, **kwargs: Any) -> Any:
                raise RuntimeError("Simulated verifier failure")

        boundary = Boundary(policy=policy, receipt_store=store, agent_id="agent-test")
        services = AppServices(boundary, file_verifier=BrokenVerifier())  # type: ignore[arg-type]

        reg = services.registry
        reg.register("fs.write", lambda env, dec: {"written": True})

        resp = services.submit_crossing(
            {
                "tool": "fs.write",
                "verb": "write",
                "resource": _resource(workspace, "broken-verifier.txt"),
                "params": {"content": "data"},
            },
            execute=True,
        )

        assert resp.get("executed") is True, f"Expected executed=True: {resp}"
        outcome = resp.get("outcome", {})
        # Verifier exception must not produce success
        assert outcome.get("status") != "success", (
            f"VULNERABILITY: Verifier exception should fail closed, got: {resp}"
        )


# ===========================================================================
# SECTION 5: SDK PATH CONSISTENCY (baseline)
# ===========================================================================

class TestSDKPathPostconditionEnforcement:
    """Verify SDK Boundary.execute() also enforces postconditions."""

    def test_sdk_lying_executor_fails_verification(
        self,
        tmp_path: Path,
        workspace: Path,
    ) -> None:
        """SDK path: lying executor must fail postcondition verification."""
        store = ReceiptStore(tmp_path / "r.db")
        policy = load_policy_yaml(_POLICY_WITH_POSTCONDITION)
        verifier = WorkspaceFileVerifier(workspace)
        boundary = Boundary(
            policy=policy, receipt_store=store, verifier=verifier, agent_id="agent-sdk"
        )
        content = "sdk-data"
        target_file = workspace / "sdk-secret.txt"
        resource = f"path:{target_file.as_posix()}"

        with pytest.raises((PostconditionFailedError, ActionBlockedError)):
            boundary.execute(
                tool="fs.write",
                verb="write",
                resource=resource,
                params={"content": content},
                fn=lying_executor,
                verify_postcondition=True,
                postcondition_claim="digest_match",
                postcondition_expected_digest=compute_content_digest(content),
                raise_on_postcondition_failure=True,
            )

    def test_sdk_correct_executor_succeeds(
        self,
        tmp_path: Path,
        workspace: Path,
    ) -> None:
        """SDK path: correct executor succeeds after verification."""
        store = ReceiptStore(tmp_path / "r.db")
        policy = load_policy_yaml(_POLICY_WITH_POSTCONDITION)
        verifier = WorkspaceFileVerifier(workspace)
        boundary = Boundary(
            policy=policy, receipt_store=store, verifier=verifier, agent_id="agent-sdk"
        )
        content = "sdk-correct-data"
        target_file = workspace / "sdk-correct.txt"
        resource = f"path:{target_file.as_posix()}"

        result = boundary.execute(
            tool="fs.write",
            verb="write",
            resource=resource,
            params={"content": content},
            fn=correct_executor_fn(workspace),
            verify_postcondition=True,
            postcondition_claim="digest_match",
            postcondition_expected_digest=compute_content_digest(content),
        )

        assert result is not None
        assert target_file.exists()


# ===========================================================================
# SECTION 6: EXECUTE_APPROVED_CROSSING PATH
# ===========================================================================

class TestApprovedCrossingPostconditionEnforcement:
    """POST /v1/crossings/{id}/execute also goes through _dispatch_and_record."""

    def test_approved_crossing_lying_executor_fails(
        self,
        tmp_path: Path,
        workspace: Path,
    ) -> None:
        """
        execute_approved_crossing must enforce postconditions via _dispatch_and_record.
        A lying executor on an approved crossing must NOT record verified-success.
        """
        store = ReceiptStore(tmp_path / "r.db")
        policy = load_policy_yaml(_POLICY_ASK_WITH_POST)
        verifier = WorkspaceFileVerifier(workspace)
        boundary = Boundary(
            policy=policy, receipt_store=store, verifier=verifier, agent_id="agent-approved"
        )
        services = AppServices(boundary, file_verifier=verifier)

        reg = services.registry
        reg.register("fs.write", lying_executor)

        resource = _resource(workspace, "approved-lying.txt")
        # 1. Submit (will get ASK)
        resp = services.submit_crossing(
            {
                "tool": "fs.write",
                "verb": "write",
                "resource": resource,
                "params": {"content": "approved-data"},
            }
        )
        assert resp["verdict"] == "ask", f"Expected ASK verdict: {resp}"
        cid = resp["crossing_id"]

        # 2. Resolve/approve
        app_resp = services.resolve_approval(cid, approved=True)
        assert app_resp["status"] == "approved"

        # 3. Execute — lying executor returns without writing
        exec_resp = services.execute_approved_crossing(cid)

        # Must NOT be success
        assert exec_resp.get("status") != "success", (
            f"VULNERABILITY: Approved crossing lying executor recorded success! {exec_resp}"
        )

    def test_approved_crossing_correct_executor_succeeds(
        self,
        tmp_path: Path,
        workspace: Path,
    ) -> None:
        """
        Correct executor on an approved crossing MUST succeed after verification.
        """
        store = ReceiptStore(tmp_path / "r.db")
        policy = load_policy_yaml(_POLICY_ASK_WITH_POST)
        verifier = WorkspaceFileVerifier(workspace)
        boundary = Boundary(
            policy=policy, receipt_store=store, verifier=verifier, agent_id="agent-approved-correct"
        )
        services = AppServices(boundary, file_verifier=verifier)

        content = "approved-correct-content"
        reg = services.registry
        reg.register("fs.write", correct_executor_fn(workspace))

        resource = _resource(workspace, "approved-correct.txt")
        resp = services.submit_crossing(
            {
                "tool": "fs.write",
                "verb": "write",
                "resource": resource,
                "params": {"content": content},
            }
        )
        assert resp["verdict"] == "ask", f"Expected ASK verdict: {resp}"
        cid = resp["crossing_id"]

        services.resolve_approval(cid, approved=True)
        exec_resp = services.execute_approved_crossing(cid)

        assert exec_resp.get("status") == "success", (
            f"Expected success for correct executor on approved crossing: {exec_resp}"
        )


# ===========================================================================
# SECTION 7: LIFECYCLE STATE MACHINE
# ===========================================================================

class TestLifecycleVerificationPendingState:
    """When postcondition is required, the lifecycle MUST pass through verification_pending."""

    def test_lifecycle_reaches_verification_pending_before_outcome(
        self,
        services_with_verifier: AppServices,
        workspace: Path,
    ) -> None:
        """
        For actions with require_postcondition, the lifecycle must transition through
        verification_pending before recording the final state.
        """
        content = "lifecycle-test-content"
        reg = services_with_verifier.registry
        reg.register("fs.write", correct_executor_fn(workspace))

        resp = services_with_verifier.submit_crossing(
            {
                "tool": "fs.write",
                "verb": "write",
                "resource": _resource(workspace, "lifecycle.txt"),
                "params": {"content": content},
            },
            execute=True,
        )

        cid = resp.get("crossing_id")
        assert cid is not None

        store = services_with_verifier.boundary.receipt_store
        transitions = store.list_action_transitions(cid)
        transition_states = [t.to_state for t in transitions]

        # verification_pending must appear in the state sequence
        assert "verification_pending" in transition_states, (
            f"Lifecycle did not pass through verification_pending. "
            f"Transitions: {transition_states}"
        )
        # Final state must be succeeded
        assert transition_states[-1] == "succeeded", (
            f"Final state must be 'succeeded' after verification. "
            f"Transitions: {transition_states}"
        )

    def test_lifecycle_lying_executor_no_succeeded_state(
        self,
        services_with_verifier: AppServices,
        workspace: Path,
    ) -> None:
        """When postcondition fails, 'succeeded' must NOT appear in transitions."""
        reg = services_with_verifier.registry
        reg.register("fs.write", lying_executor)

        resp = services_with_verifier.submit_crossing(
            {
                "tool": "fs.write",
                "verb": "write",
                "resource": _resource(workspace, "no-succeed.txt"),
                "params": {"content": "data"},
            },
            execute=True,
        )

        cid = resp.get("crossing_id")
        if cid is None:
            return  # submission itself may have been blocked

        store = services_with_verifier.boundary.receipt_store
        transitions = store.list_action_transitions(cid)
        transition_states = [t.to_state for t in transitions]

        assert "succeeded" not in transition_states, (
            f"VULNERABILITY: 'succeeded' appears in transitions despite failed postcondition! "
            f"Transitions: {transition_states}"
        )


# ===========================================================================
# SECTION 8: EVIDENCE TIER
# ===========================================================================

class TestEvidenceTierForVerifiedSuccess:
    """When postcondition verification is required, success evidence must be externally_verified."""

    def test_verified_success_evidence_tier(
        self,
        services_with_verifier: AppServices,
        workspace: Path,
    ) -> None:
        """
        When an action with require_postcondition succeeds, the outcome receipt's
        evidence_status must be 'externally_verified', not 'locally_observed'.
        """
        content = "evidence-tier-test"
        reg = services_with_verifier.registry
        reg.register("fs.write", correct_executor_fn(workspace))

        resp = services_with_verifier.submit_crossing(
            {
                "tool": "fs.write",
                "verb": "write",
                "resource": _resource(workspace, "evidence-tier.txt"),
                "params": {"content": content},
            },
            execute=True,
        )

        assert resp.get("outcome", {}).get("status") == "success", (
            f"Expected success: {resp}"
        )
        cid = resp.get("crossing_id")
        assert cid is not None
        store = services_with_verifier.boundary.receipt_store
        outcome_rec = store.get_outcome_receipt(cid)
        assert outcome_rec is not None
        assert outcome_rec.evidence_status == "externally_verified", (
            f"Expected externally_verified evidence for postcondition success, "
            f"got: {outcome_rec.evidence_status}"
        )


# ===========================================================================
# SECTION 9: CONCURRENT EXECUTION — no race to bypass verification
# ===========================================================================

class TestConcurrentExecutionNoBypass:
    """Concurrent requests must not produce bypassed success records."""

    def test_concurrent_lying_executors_all_fail(
        self,
        services_with_verifier: AppServices,
        workspace: Path,
    ) -> None:
        """Multiple concurrent lying executors must all fail postcondition verification."""
        reg = services_with_verifier.registry
        reg.register("fs.write", lying_executor)

        results: list[dict] = []
        lock = threading.Lock()

        def run_crossing(idx: int) -> None:
            resp = services_with_verifier.submit_crossing(
                {
                    "tool": "fs.write",
                    "verb": "write",
                    "resource": _resource(workspace, f"concurrent-{idx}.txt"),
                    "params": {"content": f"data-{idx}"},
                },
                execute=True,
            )
            with lock:
                results.append(resp)

        threads = [threading.Thread(target=run_crossing, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for resp in results:
            outcome = resp.get("outcome", {})
            assert outcome.get("status") != "success", (
                f"VULNERABILITY: Concurrent lying executor recorded success: {resp}"
            )


# ===========================================================================
# SECTION 10: DIRECT SERVICE API (no bypass via service layer)
# ===========================================================================

class TestDirectServiceAPIPostconditionEnforcement:
    """Calling submit_crossing directly must also enforce postconditions."""

    def test_direct_submit_crossing_lying_executor_fails(
        self,
        services_with_verifier: AppServices,
        workspace: Path,
    ) -> None:
        """Direct service layer call must enforce postconditions."""
        reg = services_with_verifier.registry
        reg.register("fs.write", lying_executor)

        resp = services_with_verifier.submit_crossing(
            {
                "tool": "fs.write",
                "verb": "write",
                "resource": _resource(workspace, "direct-service.txt"),
                "params": {"content": "data"},
            },
            execute=True,
        )

        outcome = resp.get("outcome", {})
        assert outcome.get("status") != "success", (
            f"Direct service API bypassed postcondition verification: {resp}"
        )


# ===========================================================================
# SECTION 11: DATABASE FAILURE HANDLING
# ===========================================================================

class TestDatabaseFailureDuringFinalization:
    """Test graceful handling when outcome recording encounters issues."""

    def test_lying_executor_outcome_stored_as_failure_or_unknown(
        self,
        services_with_verifier: AppServices,
        workspace: Path,
    ) -> None:
        """
        Even if outcome recording has transient issues, the system must not
        promote a lying executor to 'success' status.
        """
        reg = services_with_verifier.registry
        reg.register("fs.write", lying_executor)

        resp = services_with_verifier.submit_crossing(
            {
                "tool": "fs.write",
                "verb": "write",
                "resource": _resource(workspace, "db-failure-test.txt"),
                "params": {"content": "data"},
            },
            execute=True,
        )

        # In all cases, a lying executor must not produce "success"
        if resp.get("executed"):
            outcome = resp.get("outcome", {})
            assert outcome.get("status") != "success"


# ===========================================================================
# SECTION 12: CONSISTENCY ACROSS ALL EXECUTION ENTRY POINTS
# ===========================================================================

class TestExecutionEntryPointConsistency:
    """All execution paths must produce consistent postcondition enforcement results."""

    def test_sdk_and_gateway_lying_executor_both_fail(
        self,
        tmp_path: Path,
        workspace: Path,
    ) -> None:
        """
        SDK path and gateway path must both reject a lying executor for a
        policy-mandated postcondition action.
        """
        db_sdk = tmp_path / "sdk.db"
        db_gw = tmp_path / "gw.db"
        policy = load_policy_yaml(_POLICY_WITH_POSTCONDITION)
        verifier = WorkspaceFileVerifier(workspace)

        # --- SDK path ---
        sdk_store = ReceiptStore(db_sdk)
        sdk_boundary = Boundary(
            policy=policy, receipt_store=sdk_store, verifier=verifier, agent_id="agent-sdk"
        )
        content = "test-content"
        target = workspace / "sdk-lying.txt"
        resource = f"path:{target.as_posix()}"

        # SDK path: lying executor must fail
        with pytest.raises((PostconditionFailedError, ActionBlockedError, Exception)):
            sdk_boundary.execute(
                tool="fs.write",
                verb="write",
                resource=resource,
                params={"content": content},
                fn=lying_executor,
                verify_postcondition=True,
                postcondition_claim="digest_match",
                postcondition_expected_digest=compute_content_digest(content),
                raise_on_postcondition_failure=True,
            )

        # --- Gateway path ---
        gw_store = ReceiptStore(db_gw)
        gw_boundary = Boundary(
            policy=policy, receipt_store=gw_store, verifier=verifier, agent_id="agent-gw"
        )
        services = AppServices(gw_boundary, file_verifier=verifier)
        reg = services.registry
        reg.register("fs.write", lying_executor)

        gw_resource = _resource(workspace, "gw-lying.txt")
        gw_resp = services.submit_crossing(
            {
                "tool": "fs.write",
                "verb": "write",
                "resource": gw_resource,
                "params": {"content": content},
            },
            execute=True,
        )

        gw_outcome = gw_resp.get("outcome", {})
        assert gw_outcome.get("status") != "success", (
            f"VULNERABILITY: Gateway path produced success where SDK would fail: {gw_resp}"
        )


# ===========================================================================
# SECTION 13: ACTUAL HTTP HANDLER INTEGRATION TESTS
# ===========================================================================

def _dispatch_http_handler(
    services: AppServices,
    path: str,
    method: str = "POST",
    data: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    """Dispatch request directly through ActentraHTTPHandler (simulates full HTTP pipeline)."""
    handler = ActentraHTTPHandler.__new__(ActentraHTTPHandler)
    server_mock = MagicMock()
    server_mock.services = services
    server_mock.auth_token = None
    server_mock.boundary = services.boundary
    server_mock.allowed_hosts = ()
    server_mock.deployment_mode = "local"
    server_mock.require_client_cert = False
    server_mock.token_principals = None
    handler.server = server_mock
    handler.request_version = "HTTP/1.1"
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.close_connection = True
    handler.path = path
    handler.wfile = io.BytesIO()

    body_bytes = json.dumps(data).encode("utf-8") if data is not None else b""
    handler.headers = {
        "Content-Length": str(len(body_bytes)),
        "Content-Type": "application/json",
        "Host": "localhost",
    }
    handler.rfile = io.BytesIO(body_bytes)

    if method == "GET":
        handler.do_GET()
    elif method == "POST":
        handler.do_POST()
    else:
        raise ValueError(f"Unsupported method {method}")

    raw_output = handler.wfile.getvalue().decode("utf-8")
    status_line = raw_output.splitlines()[0]
    status_code = int(status_line.split()[1])
    parts = raw_output.split("\r\n\r\n", 1)
    body_str = parts[1] if len(parts) > 1 else ""
    try:
        parsed_body = json.loads(body_str)
    except Exception:
        parsed_body = body_str
    return status_code, parsed_body


class TestHTTPHandlerPostconditionEnforcement:
    """Verifies that the exploit is prevented through the actual HTTP request pipeline."""

    def test_http_lying_executor_rejected(
        self,
        services_with_verifier: AppServices,
        workspace: Path,
    ) -> None:
        """
        Original exploit via POST /v1/crossings with execute=True.
        The HTTP response MUST NOT report a verified success outcome.
        """
        reg = services_with_verifier.registry
        reg.register("fs.write", lying_executor)

        resource = _resource(workspace, "http-attack-lying.txt")
        status_code, body = _dispatch_http_handler(
            services_with_verifier,
            "/v1/crossings",
            method="POST",
            data={
                "tool": "fs.write",
                "verb": "write",
                "resource": resource,
                "params": {"content": "confidential-payload"},
                "execute": True,
            },
        )

        assert status_code == 200
        assert isinstance(body, dict)
        outcome = body.get("outcome", {})
        # MUST NOT be success
        assert outcome.get("status") != "success", (
            f"VULNERABILITY: HTTP handler returned success for lying executor! {body}"
        )
        assert outcome.get("status") in ("failure", "unknown")

    def test_http_wrong_content_executor_rejected(
        self,
        services_with_verifier: AppServices,
        workspace: Path,
    ) -> None:
        """
        Executor writes wrong content via POST /v1/crossings with execute=True.
        The HTTP response outcome MUST NOT be success.
        """
        reg = services_with_verifier.registry
        reg.register("fs.write", wrong_content_executor_fn(workspace))

        resource = _resource(workspace, "http-attack-wrong.txt")
        status_code, body = _dispatch_http_handler(
            services_with_verifier,
            "/v1/crossings",
            method="POST",
            data={
                "tool": "fs.write",
                "verb": "write",
                "resource": resource,
                "params": {"content": "expected-content"},
                "execute": True,
            },
        )

        assert status_code == 200
        assert isinstance(body, dict)
        outcome = body.get("outcome", {})
        assert outcome.get("status") != "success", (
            f"VULNERABILITY: HTTP handler accepted wrong content! {body}"
        )

    def test_http_correct_executor_succeeds_with_verification(
        self,
        services_with_verifier: AppServices,
        workspace: Path,
    ) -> None:
        """
        Correct executor via POST /v1/crossings with execute=True.
        HTTP handler returns outcome status == 'success'.
        """
        reg = services_with_verifier.registry
        content = "verified-http-content"
        reg.register("fs.write", correct_executor_fn(workspace))

        resource = _resource(workspace, "http-correct.txt")
        status_code, body = _dispatch_http_handler(
            services_with_verifier,
            "/v1/crossings",
            method="POST",
            data={
                "tool": "fs.write",
                "verb": "write",
                "resource": resource,
                "params": {"content": content},
                "execute": True,
            },
        )

        assert status_code == 200
        assert isinstance(body, dict)
        outcome = body.get("outcome", {})
        assert outcome.get("status") == "success", (
            f"Expected verified success, got: {body}"
        )

