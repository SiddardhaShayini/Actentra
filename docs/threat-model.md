# Actentra Threat Model (v1)

This document defines the threats Actentra is designed to mitigate, the corresponding controls, and the residual risks. It is aligned with [PLAN.md](../PLAN.md) Section 8.3.

## Trust Boundaries

1. **Agent / Model Boundary (Untrusted):** Tool calls, parameters, and declared intent originating from an LLM or agent framework are treated as untrusted proposals.
2. **External Data Boundary (Untrusted):** Inbound web pages, emails, files, and API responses carry provenance labels (`trusted`, `untrusted`, `unknown`).
3. **Actentra Kernel Boundary (Trusted Core):** `actentra_core` performs deterministic canonicalization, risk tagging, policy evaluation, and receipt logging without LLM involvement.
4. **Target System Boundary:** Filesystem, database, HTTP endpoints, or OS processes reached after Actentra authorization.

## Threat Matrix

| ID | Threat | Mitigation | Residual Risk |
| --- | --- | --- | --- |
| T1 | **Prompt injection triggers dangerous action** | Provenance labeling (`untrusted`), risk tagging (`untrusted-provenance`, `external-egress`, `destructive`), deny-overrides policy rules, `ASK` escalation | Novel multi-step flows require new policy rules; provenance depends on adapter fidelity |
| T2 | **Hallucinated or malformed parameters** | Strict envelope schema, canonicalization (`CanonicalizationError` fails closed), parameter constraints, dry-run (Phase 3) | Syntactically valid but semantically wrong values (e.g., wrong valid ID) require domain limits |
| T3 | **Confused deputy / ambient authority** | Least-privilege per-action mediation; secrets broker (Phase 1/3) so agents never hold raw credentials | Overly broad broker or policy scopes |
| T4 | **Exfiltration via chains of benign calls** | Session tracking, rate limits, cumulative budgets (Phase 3), egress allow-lists | Low-and-slow exfiltration below thresholds |
| T5 | **Runaway loops & cost blowups** | Per-session and global rate limits (`limits`), kill switch (`freeze`) | Thresholds must be tuned per workload |
| T6 | **Audit log tampering** | Append-only SQLite WAL receipts with SHA-256 hash chaining (`prev_hash` -> `entry_hash`), `verify-log`, signed checkpoints (Phase 3) | An attacker with full host write access can delete/rewrite an unanchored local DB; off-host anchoring mitigates this |
| T7 | **Malicious plugin / connector** | Narrow connector scopes; out-of-process / signed plugins planned in Phase 4 | Supply-chain trust for locally installed Python code in-process |
| T8 | **Policy bypass via encoding, traversal, or TOCTOU** | Canonicalize-then-hash-then-execute-same-bytes (`I3`), strict Windows path checks (ADS, reserved names, `..`, trailing dots/spaces, device namespaces) | Target parser differentials (e.g., SQL dialect quirks) |
| T9 | **Policy tampering on disk** | `policy check` validation, policy hash pinned in every receipt (`policy_version`), last-known-good reload (`I6`), OS permissions | Root/admin compromise on the host is out of scope |
| T10 | **Approval fatigue / approver spoofing** | Clear approval summary bound to `(session_id, canonical_hash)` with TTL (`I4`) | Human reviewer clicking approve without reading |
