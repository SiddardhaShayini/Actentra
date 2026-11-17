"""Restart-safe HTTP Gateway and Scoped Executor Demonstration for Actentra.

Demonstrates the complete Phase 1 action lifecycle:
1. Workspace fixture preparation.
2. Allowed file read via LocalFSExecutor (verdict ALLOW, outcome success).
3. Protected file deletion (verdict ASK, pending approval persisted in SQLite WAL).
4. Gateway restart: pending approval survives process recreation.
5. Explicit human approval resolution (status transitions to 'approved').
6. Second gateway restart: approved-but-not-yet-executed state survives process recreation.
7. Execution of approved crossing in restarted process (file deleted, outcome success).
8. Duplicate execution prevention: atomic claim prevents double-dispatch.
9. Denied sensitive file access (verdict DENY, zero executor calls).
10. External execution with caller-reported outcome (explicitly labeled 'caller').
11. End-to-end SQLite hash chain and envelope integrity verification.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from actentra.boundary import Boundary
from actentra_core.canonicalize import canonicalize_windows_path
from actentra_core.handoffs import UnauthorizedAgentHandoffError
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore, VerificationResult, verify_log
from actentra_core.verdict import Verdict
from actentra_gateway.services import AppServices, ExecutorRegistry

_DEMO_POLICY_YAML = """\
version: 1
policy_id: gateway-demonstration-policy
mode: enforce

defaults:
  verdict: deny
  reason: "Denied by default: action not explicitly permitted"

limits:
  - id: demo-session-rate
    scope: session
    max_actions_per_minute: 60

rules:
  - id: block-sensitive-env
    match:
      tool: "fs.*"
      resource: "path:**/.env*"
    verdict: deny
    reason: "Access to credential or secret files is strictly blocked"

  - id: block-privilege-escalation
    match:
      risk_any: [privilege-escalation]
    verdict: deny
    reason: "Privilege-escalating or sensitive-path actions are strictly blocked"

  - id: allow-workspace-reads
    match:
      tool: "fs.read"
      verb: read
    verdict: allow
    reason: "Allow safe workspace file reads"

  - id: ask-workspace-delete
    match:
      tool: "fs.delete"
      verb: delete
    verdict: ask
    reason: "File deletion requires human approval"

  - id: allow-calc-external
    match:
      tool: "calc"
      verb: read
    verdict: allow
    reason: "Allow safe computation for external execution workflow"
"""


@dataclass(frozen=True, slots=True)
class GatewayDemoResult:
    ok: bool
    workspace_dir: str
    db_path: str
    read_crossing_id: str
    read_content: str
    delete_crossing_id: str
    denied_crossing_id: str
    external_crossing_id: str
    verification: VerificationResult
    steps_executed: int
    summary: dict[str, Any]


def run_gateway_demonstration(
    *,
    workspace_dir: Path | None = None,
    db_path: Path | None = None,
    echo: Callable[[str], None] = print,
    verbose: bool = True,
) -> GatewayDemoResult:
    """Execute the end-to-end restart-safe gateway demonstration."""
    temp_ctx = None
    if workspace_dir is None or db_path is None:
        temp_ctx = tempfile.TemporaryDirectory(prefix="actentra-gateway-demo-")
        base = Path(temp_ctx.name)
        if workspace_dir is None:
            workspace_dir = base / "workspace"
        if db_path is None:
            db_path = base / "receipts.db"

    try:
        workspace_dir.mkdir(parents=True, exist_ok=True)
        notes_file = workspace_dir / "notes.txt"
        important_file = workspace_dir / "important.txt"
        env_file = workspace_dir / ".env"

        notes_file.write_text("Actentra local workspace documentation\n", encoding="utf-8")
        important_file.write_text(
            "Protected file requiring human approval to delete\n", encoding="utf-8"
        )
        env_file.write_text("SECRET_TOKEN=demo_secret_token_12345\n", encoding="utf-8")

        policy = load_policy_yaml(_DEMO_POLICY_YAML)
        session_id = "demo-session"
        agent_id = "demo-agent"

        def _make_services(active_store: ReceiptStore) -> AppServices:
            b = Boundary(
                policy=policy,
                receipt_store=active_store,
                session_id=session_id,
                agent_id=agent_id,
                framework="gateway-demo",
            )
            reg = ExecutorRegistry()
            reg.register_fs(workspace_dir)
            return AppServices(b, executor_registry=reg)

        steps = 0

        # --- STEP 1: Allowed Read ---
        if verbose:
            echo("\n[Step 1] Proposing allowed workspace read (fs.read on notes.txt)...")
        store = ReceiptStore(db_path)
        services = _make_services(store)

        read_res = services.submit_crossing(
            {
                "tool": "fs.read",
                "verb": "read",
                "resource": f"path:{notes_file.as_posix()}",
                "params": {"path": "notes.txt"},
                "session_id": session_id,
                "agent_id": agent_id,
            },
            execute=True,
        )
        steps += 1
        read_cid = read_res["crossing_id"]
        v_read = read_res["verdict"]
        assert v_read == Verdict.ALLOW.value, f"Expected ALLOW, got {v_read}"
        out_stat = read_res.get("outcome", {}).get("status")
        assert out_stat == "success", "Expected execution outcome success"
        read_content = str(read_res["outcome"]["result"])
        if verbose:
            echo(f"  -> Verdict: {read_res['verdict']} (rule={read_res['rule_id']})")
            echo(f"  -> Outcome: success (content={read_content.strip()!r})")

        # --- STEP 2: Protected Deletion (Produces ASK) ---
        if verbose:
            echo("\n[Step 2] Proposing protected file deletion (fs.delete on important.txt)...")
        del_res = services.submit_crossing(
            {
                "tool": "fs.delete",
                "verb": "delete",
                "resource": f"path:{important_file.as_posix()}",
                "params": {"path": "important.txt"},
                "session_id": session_id,
                "agent_id": agent_id,
            },
            execute=True,
        )
        steps += 1
        del_cid = del_res["crossing_id"]
        assert del_res["verdict"] == Verdict.ASK.value, f"Expected ASK, got {del_res['verdict']}"
        assert del_res.get("pending_status") == "pending", "Expected pending approval status"
        assert important_file.exists(), "Protected file must NOT be deleted prior to approval!"
        if verbose:
            echo(f"  -> Verdict: {del_res['verdict']} (rule={del_res['rule_id']})")
            echo(f"  -> Approval state: persisted pending approval (crossing_id={del_cid})")
            echo(f"  -> Pre-condition check: important.txt exists={important_file.exists()}")

        # --- STEP 3: Gateway Process Restart (Pending State Survival) ---
        if verbose:
            echo("\n[Step 3] Simulating Gateway process termination and restart on same DB...")
        del services
        del store

        # New process instantiation
        store2 = ReceiptStore(db_path)
        services2 = _make_services(store2)
        steps += 1

        pending_items = services2.list_pending_approvals(status="pending")
        matching = [p for p in pending_items if p["crossing_id"] == del_cid]
        assert len(matching) == 1, "Pending approval MUST survive gateway restart!"
        assert important_file.exists(), "Protected file must remain untouched across restart"
        if verbose:
            cnt = len(pending_items)
            echo(f"  -> Process restarted successfully. Found {cnt} pending approval(s).")
            echo(f"  -> Verified crossing {del_cid} persisted with status='pending'.")

        # --- STEP 4: Human Approval Resolution ---
        if verbose:
            echo("\n[Step 4] Human operator reviews and resolves approval (approved=True)...")
        app_res = services2.resolve_approval(del_cid, approved=True, execute=False)
        steps += 1
        assert app_res.get("status") == "approved", f"Approval resolution failed: {app_res}"
        assert important_file.exists(), (
            "Approval is an authorization grant, NOT execution! File must still exist."
        )
        if verbose:
            echo(f"  -> Approval resolved: status={app_res['status']}")
            echo(f"  -> Pre-execution invariant: important.txt exists={important_file.exists()}")

        # --- STEP 5: Second Gateway Restart (Approved-but-not-yet-executed Survival) ---
        if verbose:
            echo("\n[Step 5] Simulating second gateway restart after approval, prior to exec...")
        del services2
        del store2

        store3 = ReceiptStore(db_path)
        services3 = _make_services(store3)
        steps += 1

        app_rec = store3.get_pending_approval(del_cid)
        assert app_rec is not None, "Approved record missing after restart"
        assert app_rec.status == "approved", f"Expected approved status, got {app_rec.status}"
        assert important_file.exists(), "File still exists before explicit execution command."
        if verbose:
            echo(f"  -> Reopened database: crossing {del_cid} verified in 'approved' state.")

        # --- STEP 6: Execute Approved Crossing in Restarted Process ---
        if verbose:
            echo("\n[Step 6] Dispatching execution of approved crossing in restarted process...")
        exec_res = services3.execute_approved_crossing(del_cid)
        steps += 1
        assert exec_res.get("status") == "success", f"Execution failed: {exec_res}"
        assert not important_file.exists(), "File MUST now be deleted by the scoped executor!"
        if verbose:
            echo("  -> Execution dispatched to LocalFSExecutor.")
            echo(f"  -> Post-check: important.txt exists={important_file.exists()} (deleted)")

        # --- STEP 7: Duplicate Execution Prevention (Atomic Claim) ---
        if verbose:
            echo("\n[Step 7] Attempting duplicate execution of already-consumed crossing...")
        dup_res = services3.execute_approved_crossing(del_cid)
        steps += 1
        assert "error" in dup_res, "Duplicate execution MUST be rejected fail-closed!"
        if verbose:
            echo(f"  -> Duplicate execution rejected: {dup_res['error']}")

        # --- STEP 8: Denied Variant (Sensitive Path Traversal) ---
        if verbose:
            echo("\n[Step 8] Proposing access to sensitive credential file (.env)...")
        deny_res = services3.submit_crossing(
            {
                "tool": "fs.read",
                "verb": "read",
                "resource": f"path:{env_file.as_posix()}",
                "params": {"path": ".env"},
                "session_id": session_id,
                "agent_id": agent_id,
            },
            execute=True,
        )
        steps += 1
        deny_cid = deny_res["crossing_id"]
        v_deny = deny_res["verdict"]
        assert v_deny == Verdict.DENY.value, f"Expected DENY, got {v_deny}"
        assert "outcome" not in deny_res or deny_res.get("outcome") is None, (
            "Executor must NEVER be called on DENY"
        )
        if verbose:
            r_id = deny_res["rule_id"]
            reason = deny_res["reason"]
            echo(f"  -> Verdict: {v_deny} (rule={r_id}, reason={reason})")
            echo("  -> Executor was not called; decision receipt committed to SQLite chain.")

        # --- STEP 9: External Execution with Caller-Reported Outcome ---
        if verbose:
            echo("\n[Step 9] Demonstrating external execution with caller-reported outcome...")
        ext_res = services3.submit_crossing(
            {
                "tool": "calc",
                "verb": "read",
                "resource": "tool:calc",
                "params": {"expression": "21 * 2"},
                "session_id": session_id,
                "agent_id": agent_id,
            },
            execute=False,
        )
        steps += 1
        ext_cid = ext_res["crossing_id"]
        assert ext_res["verdict"] == Verdict.ALLOW.value

        out_rep = services3.record_external_outcome(
            ext_cid,
            status="success",
            result_hash="sha256:4242424242424242424242424242424242424242424242424242424242424242",
        )
        steps += 1
        assert out_rep.get("status") == "recorded"
        assert out_rep.get("reported_by") == "caller"
        if verbose:
            echo(f"  -> External outcome recorded: reported_by={out_rep['reported_by']}")
            echo("  -> Clearly distinguished from Actentra-registered executor evidence.")

        # --- STEP 10: End-to-End Cryptographic Audit Verification ---
        if verbose:
            echo("\n[Step 10] Performing cryptographic hash chain and envelope verification...")
        vr = verify_log(db_path, verify_envelopes=True)
        steps += 1
        assert vr.ok, f"Audit log verification failed: {vr.errors}"
        assert vr.total_records >= 6, f"Expected at least 6 receipt records, got {vr.total_records}"
        if verbose:
            echo(f"  -> Log Verification: ok={vr.ok} total_records={vr.total_records}")
            echo(f"  -> Head hash: {vr.last_hash}")

        summary = {
            "total_steps": steps,
            "total_receipts": vr.total_records,
            "chain_head": vr.last_hash,
            "read_file_result": read_content.strip(),
            "protected_file_deleted": not important_file.exists(),
        }

        if verbose:
            echo("\n[Summary] Gateway demonstration completed successfully with 100% compliance!")

        return GatewayDemoResult(
            ok=True,
            workspace_dir=str(workspace_dir),
            db_path=str(db_path),
            read_crossing_id=read_cid,
            read_content=read_content,
            delete_crossing_id=del_cid,
            denied_crossing_id=deny_cid,
            external_crossing_id=ext_cid,
            verification=vr,
            steps_executed=steps,
            summary=summary,
        )

    finally:
        if temp_ctx is not None:
            pass


@dataclass(frozen=True, slots=True)
class HandoffDemoResult:
    """Result of the cross-agent continuity handoff demonstration."""

    ok: bool
    workspace_dir: str
    db_path: str
    task_id: str
    handoff_step1_id: str
    handoff_step2_id: str
    write_crossing_id: str
    read_crossing_id: str
    unauthorized_blocked: bool
    independent_verified: bool
    drift_detected: bool
    steps_executed: int
    causal_trace: dict[str, Any]


_HANDOFF_DEMO_POLICY_YAML = """\
version: 1
policy_id: handoff-demonstration-policy
mode: enforce

defaults:
  verdict: deny
  reason: "Denied by default: unpermitted action"

rules:
  - id: allow-fs-reads
    match:
      tool: "fs.read"
      verb: read
    verdict: allow
    reason: "Allow workspace file reads"

  - id: allow-fs-writes
    match:
      tool: "fs.write"
      verb: write
    verdict: allow
    reason: "Allow workspace file writes"
"""


def run_handoff_demonstration(
    *,
    workspace_root: str | Path | None = None,
    db_file: str | Path | None = None,
    verbose: bool = True,
    echo_fn: Callable[[str], None] | None = None,
) -> HandoffDemoResult:
    """Execute the Phase 4 constrained cross-agent handoff demonstration."""
    echo = echo_fn or print
    temp_ctx = None
    if workspace_root is None:
        temp_ctx = tempfile.TemporaryDirectory(prefix="actentra_handoff_demo_")
        workspace_dir = Path(temp_ctx.name).resolve()
    else:
        workspace_dir = Path(workspace_root).resolve()
        workspace_dir.mkdir(parents=True, exist_ok=True)

    db_path = (
        Path(db_file).resolve()
        if db_file is not None
        else (workspace_dir / "handoff_demo.db").resolve()
    )

    steps = 0
    try:
        if verbose:
            echo("=== Actentra Phase 4 Cross-Agent Continuity Demonstration ===")
            echo(f"Workspace: {workspace_dir}")
            echo(f"Database:  {db_path}")

        policy = load_policy_yaml(_HANDOFF_DEMO_POLICY_YAML)
        task_id = "task_release_pipeline_001"

        def _make_services(active_store: ReceiptStore) -> AppServices:
            b = Boundary(
                policy=policy,
                receipt_store=active_store,
                session_id="handoff-session",
                agent_id="agent_planner",
                framework="handoff-demo",
            )
            reg = ExecutorRegistry()
            reg.register_fs(workspace_dir)
            return AppServices(b, executor_registry=reg)

        store1 = ReceiptStore(db_path)
        services1 = _make_services(store1)

        # --- STEP 1: Agent A (Initiator) writes release manifest and creates handoff ---
        if verbose:
            echo("\n[Step 1] Agent A ('agent_planner') initiates task and writes manifest...")
        manifest_file = workspace_dir / "release_manifest.json"
        manifest_canon = canonicalize_windows_path(str(manifest_file))
        manifest_res = f"path:{manifest_canon}"
        manifest_text = '{"version": "1.0.0", "target": "release"}\n'

        submit_resp1 = services1.submit_crossing(
            {
                "tool": "fs.write",
                "verb": "write",
                "resource": manifest_res,
                "params": {"content": manifest_text},
                "agent_id": "agent_planner",
            },
            execute=True,
        )
        assert submit_resp1.get("verdict") == "allow"
        assert submit_resp1.get("executed") is True
        write_cid = str(submit_resp1["crossing_id"])
        steps += 1

        import hashlib
        manifest_digest = f"sha256:{hashlib.sha256(manifest_text.encode('utf-8')).hexdigest()}"

        hnd1 = services1.create_task_handoff(
            task_id=task_id,
            initiator_agent_id="agent_planner",
            assigned_agent_id="agent_builder",
            verifier_agent_id="agent_auditor",
            allowed_verbs=["read", "write"],
            allowed_resources=[manifest_res, f"path:{workspace_dir.as_posix().lower()}/*"],
            prior_crossings=[write_cid],
            assertions={manifest_res: {"claim": "exists", "digest": manifest_digest}},
        )
        hnd1_id = hnd1["handoff_id"]
        steps += 1
        if verbose:
            echo(f"  -> Crossing {write_cid} ALLOWED and executed.")
            echo(
                f"  -> Created Task Handoff {hnd1_id} for {task_id} (assigned to 'agent_builder')."
            )

        # --- STEP 2: Gateway Restart Simulation ---
        if verbose:
            echo("\n[Step 2] Simulating process restart: recreating AppServices from SQLite...")
        del services1
        del store1

        store2 = ReceiptStore(db_path)
        services2 = _make_services(store2)
        hnd1_reloaded = services2.get_task_handoff(hnd1_id)
        assert hnd1_reloaded is not None
        assert hnd1_reloaded["status"] == "active"
        assert hnd1_reloaded["assigned_agent_id"] == "agent_builder"
        steps += 1
        if verbose:
            echo("  -> Process restart successful: task handoff persisted in SQLite WAL.")

        # --- STEP 3: Unauthorized Agent Attempt ---
        if verbose:
            echo("\n[Step 3] Unauthorized Agent X ('agent_rogue') attempts to advance handoff...")
        unauth_blocked = False
        try:
            services2.advance_task_handoff(
                hnd1_id,
                caller_agent_id="agent_rogue",
                next_agent_id="agent_auditor",
            )
        except UnauthorizedAgentHandoffError:
            unauth_blocked = True
        assert unauth_blocked, "Expected UnauthorizedAgentHandoffError for unassigned caller"
        steps += 1
        if verbose:
            echo("  -> Unauthorized agent rejected fail-closed (UnauthorizedAgentHandoffError)!")

        # --- STEP 4: Authorized Agent B continues and advances handoff ---
        if verbose:
            echo(
                "\n[Step 4] Authorized Agent B ('agent_builder') "
                "reads manifest and builds output..."
            )
        read_resp = services2.submit_crossing(
            {
                "tool": "fs.read",
                "verb": "read",
                "resource": manifest_res,
                "agent_id": "agent_builder",
            },
            execute=True,
        )
        assert read_resp.get("executed") is True
        read_cid = str(read_resp["crossing_id"])

        output_file = workspace_dir / "build_output.txt"
        output_canon = canonicalize_windows_path(str(output_file))
        output_res = f"path:{output_canon}"
        output_text = "BUILD SUCCESS: version 1.0.0 release packages compiled\n"

        write_resp2 = services2.submit_crossing(
            {
                "tool": "fs.write",
                "verb": "write",
                "resource": output_res,
                "params": {"content": output_text},
                "agent_id": "agent_builder",
            },
            execute=True,
        )
        assert write_resp2.get("executed") is True
        output_cid = str(write_resp2["crossing_id"])
        output_digest = f"sha256:{hashlib.sha256(output_text.encode('utf-8')).hexdigest()}"

        hnd2 = services2.advance_task_handoff(
            hnd1_id,
            caller_agent_id="agent_builder",
            next_agent_id="agent_auditor",
            crossing_id=output_cid,
            new_assertions={output_res: {"claim": "exists", "digest": output_digest}},
        )
        hnd2_id = hnd2["handoff_id"]
        assert hnd2["current_step"] == 2
        steps += 1
        if verbose:
            echo(f"  -> Agent B read crossing: {read_cid}")
            echo(f"  -> Agent B write crossing: {output_cid}")
            echo(f"  -> Advanced handoff to Step 2 ({hnd2_id}), assigned to 'agent_auditor'.")

        # --- STEP 5: Independent Verification by Agent C ---
        if verbose:
            echo("\n[Step 5] Verifier Agent C ('agent_auditor') independently checks state...")
        verify_res1 = services2.verify_task_handoff(
            hnd2_id,
            verifier_agent_id="agent_auditor",
        )
        assert verify_res1["verified"] is True
        assert verify_res1["status"] == "completed"
        assert len(verify_res1["contradictions"]) == 0
        steps += 1
        if verbose:
            echo(
                "  -> Independent verification PASSED: "
                "WorkspaceFileVerifier observed digests match."
            )

        # --- STEP 6: Evidence Drift & Contradiction Detection ---
        if verbose:
            echo("\n[Step 6] Simulating out-of-band tampering / drift on build_output.txt...")
        output_file.write_text("TAMPERED CONTENT: unofficial modification\n", encoding="utf-8")

        # Create a fresh step to verify with stale/tampered assertion
        hnd3 = services2.create_task_handoff(
            task_id=task_id,
            initiator_agent_id="agent_builder",
            assigned_agent_id="agent_auditor",
            verifier_agent_id="agent_auditor",
            assertions={output_res: {"claim": "exists", "digest": output_digest}},
        )
        verify_res2 = services2.verify_task_handoff(
            hnd3["handoff_id"],
            verifier_agent_id="agent_auditor",
        )
        assert verify_res2["verified"] is False
        assert verify_res2["status"] == "contradicted"
        assert len(verify_res2["contradictions"]) > 0
        steps += 1
        if verbose:
            echo(
                "  -> DRIFT DETECTED: Verifier refused corrupt state "
                "and marked status 'contradicted'!"
            )
            for c in verify_res2["contradictions"]:
                echo(f"     * {c}")

        # --- STEP 7: Inspect Complete Causal Trace ---
        if verbose:
            echo("\n[Step 7] Reconstructing complete causal trace for task...")
        trace = services2.get_causal_trace(task_id)
        assert trace["dag_verified"] is True
        steps += 1
        if verbose:
            echo(f"  -> DAG Verified: {trace['dag_verified']}")
            echo(f"  -> Total causal nodes: {len(trace['nodes'])}")
            echo(f"  -> Total timeline events: {len(trace['timeline'])}")

        return HandoffDemoResult(
            ok=True,
            workspace_dir=str(workspace_dir),
            db_path=str(db_path),
            task_id=task_id,
            handoff_step1_id=hnd1_id,
            handoff_step2_id=hnd2_id,
            write_crossing_id=write_cid,
            read_crossing_id=read_cid,
            unauthorized_blocked=unauth_blocked,
            independent_verified=True,
            drift_detected=True,
            steps_executed=steps,
            causal_trace=trace,
        )

    finally:
        if temp_ctx is not None:
            temp_ctx.cleanup()

