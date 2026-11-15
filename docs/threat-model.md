# Actentra Threat Model (v1)

This document defines the threats Actentra is designed to mitigate, the corresponding controls, and the residual risks. It is aligned with [PLAN.md](../PLAN.md) Section 8.3 and [PLAN_V3.md](../PLAN_V3.md).

## Trust Boundaries

1. **Agent / Model Boundary (Untrusted):** Tool calls, parameters, and declared intent originating from an LLM or agent framework are treated as untrusted proposals.
2. **External Data Boundary (Untrusted):** Inbound web pages, emails, files, and API responses carry provenance labels (`trusted`, `untrusted`, `unknown`).
3. **Actentra Kernel Boundary (Trusted Core):** `actentra_core` performs deterministic canonicalization, risk tagging, policy evaluation, and receipt logging without LLM involvement.
4. **Target System Boundary:** Filesystem, database, HTTP endpoints, or OS processes reached after Actentra authorization.

## Threat Matrix

| ID | Threat | Mitigation | Residual Risk |
| --- | --- | --- | --- |
| T1 | **Prompt injection triggers dangerous action** | Provenance labeling (`untrusted`), dynamic session taint propagation, risk tagging (`untrusted-provenance`, `external-egress`, `destructive`), deny-overrides policy rules, `ASK` escalation | Novel multi-step flows require new policy rules; provenance depends on adapter/host fidelity |
| T2 | **Hallucinated or malformed parameters** | Strict envelope schema, canonicalization (`CanonicalizationError` fails closed), parameter constraints, dry-run simulation | Syntactically valid but semantically wrong values (e.g., wrong valid ID) require domain limits |
| T3 | **Confused deputy / ambient authority** | Least-privilege per-action mediation; DPAPI-backed `SecretsBroker` dynamically resolves `secret:<NAME>` references at executor dispatch time; secrets never exist in agent prompts, envelopes, or policies | Overly broad broker or policy scopes |
| T4 | **Exfiltration via chains of benign calls** | Dynamic session taint tracking, per-minute rate limits, cumulative session budgets (`max_actions`, `max_external_calls`, `max_egress_bytes`), egress destination allowlists | Low-and-slow exfiltration below thresholds across multiple unlinked sessions |
| T5 | **Runaway loops & cost blowups** | Per-session and global rate limits (`limits`), cumulative session action caps, kill switch (`freeze`) | Thresholds must be tuned per workload |
| T6 | **Audit log tampering** | Append-only SQLite WAL receipts with SHA-256 hash chaining (`prev_hash` -> `entry_hash`), dual-layer context verification (`actentra verify-log -e`), bounded archival (`actentra archive-log`), signed Ed25519 checkpoints | An attacker with full host write access can delete/rewrite an unanchored local DB; off-host signed checkpoint anchoring mitigates this |
| T7 | **Malicious plugin / connector** | Narrow connector scopes, strict filesystem sandboxing, and loopback-only executor dispatch | Supply-chain trust for locally installed Python dependencies in-process |
| T8 | **Policy bypass via encoding, traversal, or TOCTOU** | Canonicalize-then-hash-then-execute-same-bytes (`I3`), strict Windows path checks (ADS, reserved names, `..`, trailing dots/spaces, device namespaces) | Target parser differentials (e.g., SQL dialect quirks) |
| T9 | **Policy tampering on disk** | `policy check` validation, policy hash pinned in every receipt (`policy_version`), last-known-good reload (`I6`), OS permissions | Root/admin compromise on the host is out of scope |
| T10 | **Approval fatigue / approver spoofing** | Clear approval summary bound to `(session_id, canonical_hash)` with TTL (`I4`), atomic single-use claim on dispatch, rejection of default/empty approval | Human reviewer clicking approve without reading |
| T11 | **Capability delegation hijack / Warrant tampering & replay** | Ed25519 asymmetric signature verification, holder matching (`expected_holder=agent_id`), expiration checks, tool/resource scope enforcement, and atomic quota consumption tracking in `WarrantRegistry` (`warrant:exhausted` fail-closed) | Compromise of root issuing key; agent impersonation if agent ID is unauthenticated |
| T12 | **SSRF / Cloud metadata exfiltration & redirect bypass** | `SSRFSafeRedirectHandler` and strict URL validation in `ScopedHTTPExecutor`: scheme checking (HTTP/HTTPS only), blocking private, loopback, link-local, and cloud metadata (`169.254.169.254`) IP ranges before connect and on every redirect hop, strict max redirects limit | DNS rebinding attacks on dynamic public domains resolving to private IPs if DNS caching/pinning is not used |
