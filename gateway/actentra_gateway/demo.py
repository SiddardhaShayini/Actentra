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
