"""Minimal local Python example: policy-gated, postcondition-verified file write.

Run anywhere after installing Actentra (no server or repository files required):
    python minimal_file_write.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from actentra import Boundary, path_resource


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="actentra-write-demo-") as tmp:
        root = Path(tmp).resolve()
        workspace = root / "workspace"
        workspace.mkdir()
        db_path = root / "receipts.db"
        ws_pattern = path_resource(workspace).removeprefix("path:")

        policy_yaml = f"""\
version: 1
policy_id: minimal-write-demo
mode: enforce

defaults:
  verdict: deny
  reason: "Denied by default policy"

rules:
  - id: ask-workspace-write
    match:
      tool: fs.write
      verb: write
      resource: "path:{ws_pattern}/**"
    verdict: ask
    reason: "Workspace writes require explicit approval"
"""

        # Explicit approval callback bound to the exact action hash (Invariant I4).
        # In interactive CLI apps, pass `approval_callback=cli_approval_prompt`.
        def approve_write(envelope, decision) -> bool:
            print(
                f"[APPROVAL] tool={envelope.action.tool} resource={envelope.action.resource} "
                f"hash={envelope.canonical_hash[:24]}... rule={decision.rule_id}"
            )
            return True

        # 1. Initialize local boundary with workspace executor & verifier enabled
        boundary = Boundary.from_yaml(
            policy_yaml=policy_yaml,
            receipts_db=db_path,
            workspace_root=workspace,
            session_id="example-write-session",
            agent_id="file-writer-agent",
            approval_callback=approve_write,
        )

        # 2. Request a scoped, postcondition-verified file write
        target_resource = path_resource("notes/hello.txt", workspace_root=workspace)
        exec_res = boundary.run(
            tool="fs.write",
            verb="write",
            resource=target_resource,
            params={
                "content": "Hello from Actentra!\n",
                "create_parents": True,
            },
            verify_postcondition=True,
            raise_on_postcondition_failure=True,
        )

        print("\n=== Execution Result ===")
        print(f"Crossing ID     : {exec_res.crossing_id}")
        print(f"Allowed         : {exec_res.allowed}")
        print(f"Verdict         : {exec_res.verdict.value} (rule={exec_res.rule_id})")
        print(f"Outcome Status  : {exec_res.status}")
        print(f"Evidence Status : {exec_res.evidence_status}")
        print(f"Verified        : {exec_res.verified}")
        print(f"Executor Output : {exec_res.result}")

        # 3. Inspect the durable receipt & verify the SQLite hash chain
        receipt = boundary.inspect_crossing(exec_res.crossing_id)
        print("\n=== Receipt Inspection ===")
        print(f"Lifecycle State : {receipt.lifecycle_state}")
        print(f"Decision Entry  : {receipt.decision.entry_hash if receipt.decision else None}")
        print(f"Outcome Entry   : {receipt.outcome.entry_hash if receipt.outcome else None}")
        if receipt.observation is not None:
            print(
                f"Observation     : {receipt.observation.claim} -> {receipt.observation.status} "
                f"({receipt.observation.observed_digest})"
            )

        integrity = boundary.verify_receipts(verify_envelopes=True)
        print(f"\nHash-Chain Check: ok={integrity.ok}, records={integrity.total_records}")


if __name__ == "__main__":
    main()
