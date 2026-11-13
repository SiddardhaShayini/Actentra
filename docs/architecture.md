# Actentra Architecture & System Design

```
+-------------------------------------------------------------------------+
|                              Agent / Model                              |
|          (LangChain, OpenAI, MCP Client, Custom In-Process Agent)       |
+-------------------------------------------------------------------------+
                                    │
                         Tool Call (JSON / kwargs)
                                    ▼
+-------------------------------------------------------------------------+
| [Layer 1] Interceptors & Adapters                                        |
|   - In-Process Boundary & @guard decorator                             |
|   - FunctionCallAdapter (OpenAI / Anthropic format)                     |
|   - LangChainToolWrapper (.invoke / .run duck-typed adapter)             |
|   - MCPStdioProxy (anti-rug-pull schema pinning for CVE-2025-54136)     |
|   - HTTP Gateway (/v1/crossings REST API + /ui Operator Console)        |
+-------------------------------------------------------------------------+
                                    │
                                    ▼
+-------------------------------------------------------------------------+
| [Layer 2] Action Canonicalization & Envelope Builder                     |
|   - Windows path canonicalization (rejects ADS, 8.3, COM/LPT, traversal)|
|   - URL canonicalization (SSRF defense, metadata & private IP reject)   |
|   - SQL normalization (single-statement check, parameter extraction)    |
|   - ActionEnvelope construction & canonical SHA-256 hash calculation    |
+-------------------------------------------------------------------------+
                                    │
                                    ▼
+-------------------------------------------------------------------------+
| [Layer 3] Context, Provenance & Taint Resolver                           |
|   - Dynamic session taint tracking (indirect prompt injection defense)  |
|   - Provenance inheritance (untrusted input -> tainted session)         |
|   - Cryptographic capability token verification (Warrants)              |
+-------------------------------------------------------------------------+
                                    │
                                    ▼
+-------------------------------------------------------------------------+
| [Layer 4] Risk Engine (Deterministic, Zero-LLM)                          |
|   - Rule-based risk tagging: destructive, external-egress, bulk,        |
|     privilege-escalation, runaway-loop, budget-exceeded                 |
+-------------------------------------------------------------------------+
                                    │
                                    ▼
+-------------------------------------------------------------------------+
| [Layer 5] Policy Engine (Strictly Fail-Closed)                           |
|   - Deny-overrides first-match evaluation                                |
|   - Per-minute rate limits                                               |
|   - Cumulative session budgets (max_actions, max_external, max_bytes)    |
|   - Kill switch (freeze / unfreeze)                                      |
+-------------------------------------------------------------------------+
                                    │
           ┌────────────────────────┴────────────────────────┐
           ▼                                                 ▼
       [Verdict]                                         [Verdict]
   DENY / HOLD / ASK                                       ALLOW
           │                                                 │
   (If ASK, escalate                                         │
   to Human Approval)                                        │
           │                                                 │
           ▼                                                 ▼
+---------------------------------------+ +-------------------------------+
| [Layer 6] Approval Service            | | [Layer 7] Scoped Executors    |
|   - Cryptographically bound to exact  | |   - LocalFSExecutor (sandbox) |
|     (session_id, canonical_hash)      | |   - ScopedHTTPExecutor (SSRF) |
|   - Local Operator Web Console (/ui)  | |   - ScopedSQLiteExecutor (ro) |
|   - One-time consumption on use       | |   - SecretsBroker (DPAPI)     |
+---------------------------------------+ +-------------------------------+
                                                         │
                                                         ▼
+-------------------------------------------------------------------------+
| [Layer 8] Tamper-Evident Receipts & Log Engine                           |
|   - SQLite WAL hash chain (SHA-256)                                     |
|   - Invariant I5: Decision receipt committed before tool execution      |
|   - Outcome receipt committed post-execution (success, failure, unknown)|
|   - Signed Ed25519 Checkpoints                                          |
|   - Zero-CDN standalone HTML audit reports                              |
|   - Policy Canary replay diff engine                                    |
+-------------------------------------------------------------------------+
```

---

## The Core System Invariants

* **Invariant I1:** No code path from adapter to executor bypasses the policy engine.
* **Invariant I2:** Any error, timeout, unknown type, or corrupt state results in `DENY` or `HOLD` (strictly fail-closed).
* **Invariant I3:** The executed action hash strictly equals the evaluated action hash.
* **Invariant I4:** An approval grant is valid only for one `(session_id, canonical_hash)` pair and expires after TTL.
* **Invariant I5:** No action executes unless its decision receipt is durable; each execution attempt records an immutable outcome record.
* **Invariant I6:** Policy updates never apply partially; invalid policies are rejected while preserving the last-known-good configuration.
* **Invariant I7:** Secrets managed by the Secrets Broker never appear in logs, error messages, or envelopes returned to the agent.
