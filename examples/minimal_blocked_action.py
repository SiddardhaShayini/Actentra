"""Minimal local Python example: unauthorized actions blocked fail-closed.

Demonstrates:
1. Sensitive credential path (.env) blocked with DENY (ActionBlockedError).
2. Unapproved file write blocked when no approval is granted (ExecutionResult allowed=False).
3. Path traversal escape rejected during canonicalization (CanonicalizationError).
4. Durable decision receipts and hash-chain verification for blocked attempts.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from actentra import ActionBlockedError, Boundary, CanonicalizationError, path_resource


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="actentra-blocked-demo-") as tmp:
        root = Path(tmp)
        workspace = root / "workspace"
        workspace.mkdir()
        (workspace / ".env").write_text("API_KEY=do_not_read\n", encoding="utf-8")
        db_path = root / "receipts.db"
        ws_pattern = path_resource(workspace).removeprefix("path:")

        policy_yaml = f"""\
version: 1
policy_id: minimal-blocked-demo
mode: enforce

defaults:
  verdict: deny
  reason: "Denied by default policy"

rules:
  - id: block-privilege-escalation
    match:
      risk_any: [privilege-escalation]
    verdict: deny
    reason: "Privilege-escalating or sensitive-path actions are blocked"

  - id: allow-workspace-reads
    match:
      tool: fs.read
      verb: read
      resource: "path:{ws_pattern}/**"
    verdict: allow
    reason: "Allow workspace reads"

  - id: ask-workspace-writes
    match:
      tool: fs.write
      verb: write
      resource: "path:{ws_pattern}/**"
    verdict: ask
    reason: "Workspace writes require human approval"
"""

        boundary = Boundary.from_yaml(
            policy_yaml=policy_yaml,
            receipts_db=db_path,
            workspace_root=workspace,
            session_id="example-blocked-session",
            agent_id="untrusted-agent",
        )

        # 1. Sensitive file read (.env) raises ActionBlockedError (fail-closed DENY)
        print("[1] Attempting to read .env inside workspace...")
        try:
            boundary.run(
                tool="fs.read",
                verb="read",
                resource=path_resource(".env", workspace_root=workspace),
            )
            raise AssertionError("Expected .env read to be blocked")
        except ActionBlockedError as exc:
            print(f"  Blocked as expected: {exc}")
            rec = boundary.inspect_crossing(exc.crossing_id)
            print(
                f"  Decision receipt   : verdict={rec.decision.verdict if rec.decision else None}, "
                f"lifecycle={rec.lifecycle_state}"
            )

        # 2. Unapproved write returns blocked result when raise_on_blocked=False
        print("\n[2] Attempting unapproved fs.write with raise_on_blocked=False...")
        write_res = boundary.run(
            tool="fs.write",
            verb="write",
            resource=path_resource("blocked.txt", workspace_root=workspace),
            params={"content": "should not be written"},
            raise_on_blocked=False,
        )
        print(
            f"  allowed={write_res.allowed}, verdict={write_res.verdict.value}, "
            f"rule={write_res.rule_id}, file_exists={(workspace / 'blocked.txt').exists()}"
        )

        # 3. Path traversal escape fails closed before evaluation
        print("\n[3] Attempting workspace path traversal (../outside.txt)...")
        try:
            path_resource("../outside.txt", workspace_root=workspace)
            raise AssertionError("Expected traversal to fail")
        except CanonicalizationError as exc:
            print(f"  Rejected at canonicalization: {exc}")

        # 4. Verify audit log integrity
        integrity = boundary.verify_receipts(verify_envelopes=True)
        print(f"\nHash-Chain Check: ok={integrity.ok}, records={integrity.total_records}")


if __name__ == "__main__":
    main()
