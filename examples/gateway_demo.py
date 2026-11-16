"""Actentra Gateway Demonstration Script.

Runs the complete restart-safe action lifecycle:
- Workspace file read (allowed)
- Protected file deletion (held for human approval)
- Process termination & restart (approval survives in SQLite WAL)
- Explicit human approval grant
- Second process restart (approval state survives prior to execution)
- Execution of approved crossing in new process (file deleted)
- Duplicate execution rejection (atomic claim)
- Sensitive path denial (fail closed)
- External caller outcome recording
- Cryptographic hash-chain integrity verification
"""

from __future__ import annotations

import sys

from actentra_gateway.demo import run_gateway_demonstration


def main() -> None:
    print("=================================================================")
    print("Actentra — Restart-Safe Action & Verification Gateway Demo")
    print("=================================================================")
    result = run_gateway_demonstration(verbose=True)
    if result.ok:
        print("\nDemonstration completed successfully.")
        total_rec = result.summary["total_receipts"]
        print(f"Receipt log verified with {total_rec} tamper-evident records.")
        print(f"Head entry hash: {result.summary['chain_head']}")
        sys.exit(0)
    else:
        print("\nDemonstration failed.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
