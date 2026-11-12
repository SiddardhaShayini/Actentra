# Guarantees and Explicit Limits

Actentra follows an **honest guarantees** model: we state clearly what the kernel enforces (verified by automated tests) and what lies outside its trust boundary.

## Core Invariants (I1–I7)

| ID | Invariant | Enforcement Mechanism |
| --- | --- | --- |
| **I1** | No code path from adapter to executor bypasses policy evaluation | `Boundary.execute` / `@Boundary.guard` always builds an `ActionEnvelope` and evaluates `PolicyEngine` before invoking the action |
| **I2** | Any error, invalid envelope, or unavailable receipt store fails closed | Invalid envelopes and storage failures produce `HOLD` / `DENY` and raise `ActionBlockedError` |
| **I3** | Executed action hash equals evaluated action hash | `compute_action_hash` is re-verified immediately prior to execution; connectors receive the canonicalized `ActionEnvelope` |
| **I4** | Approval is valid only for one `canonical_hash`, one session, and before expiry | `ApprovalGrant` keys on `(session_id, canonical_hash)`, checks monotonic TTL, and is consumed on use |
| **I5** | No action executes unless its decision record is durable; every execution attempt gets an outcome record | `ReceiptStore.record_decision` commits with SQLite WAL `synchronous=FULL` before execution; `record_outcome` logs `success`, `failure`, or `unknown` (including crash recovery) |
| **I6** | Invalid policy never replaces last-known-good | `PolicyStore.reload_*` validates the full candidate policy before swapping the active `PolicyEngine` |
| **I7** | Secrets never appear in envelopes, receipts, or agent error messages | Failure outcomes record exception type names rather than raw tracebacks; secret-broker values are never placed into `ActionEnvelope` |

## What Actentra Cannot Do

1. **Make a model correct:** Actentra enforces boundaries on tool calls; it does not prevent an LLM from reasoning poorly within allowed bounds.
2. **Protect unmediated paths:** If an agent holds direct filesystem permissions, raw API keys, or unguarded subprocess access outside Actentra, Actentra cannot mediate those calls.
3. **Defend against a fully compromised host:** If an attacker has Administrator/root control over the OS running Actentra, they can bypass in-process boundaries and alter local files.
4. **Replace OS/Cloud IAM:** Actentra complements IAM by adding deterministic per-call intent, risk, taint, and approval checks.
