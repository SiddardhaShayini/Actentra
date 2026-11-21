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
* **Invariant I8:** Principal authority requires authenticated identity binding; delegation grants enforce bidirectional binding (`grant.delegator_id == delegator` and `grant.delegatee_id == authenticated_caller`), cryptographic/registry verification, scope attenuation, and nested depth limits.

---

## Operational Maintenance & Production Lifecycle

Actentra is designed for local-first, low-overhead operation on resource-constrained host machines (Windows 11, Intel i5, 8 GB RAM, CPU-only). Maintenance operations are strictly bounded in memory and time.

### 1. SQLite WAL & Hot Backup Strategy
- **Concurrency & Resilience:** The audit receipt engine operates SQLite in Write-Ahead Logging (`WAL`) mode (`journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`). WAL allows concurrent zero-copy readers alongside a single active writer without lock contention.
- **Hot Online Backups:** Operators can take consistent point-in-time snapshots of a live Actentra audit database without stopping the gateway daemon using SQLite's online backup capability:
  ```bash
  sqlite3 receipts.db "VACUUM INTO 'backups/receipts_backup.db'"
  ```
  This creates a compacted, verified replica of the database with intact hash chains and envelope linkages.
- **WAL Checkpointing:** Automatic checkpointing flushes WAL pages back into the main database file; operators can force a complete flush if needed via `PRAGMA wal_checkpoint(TRUNCATE)`.

### 2. Audit Log Partitioning & Streaming Archival
- **Bounded Iteration:** `ReceiptStore.iter_records_stream()` retrieves audit records using cursor-bounded batching (`fetchmany`), maintaining $O(1)$ memory consumption regardless of database size.
- **Archival Command:** When logs grow large, historical records before a given sequence number can be cleanly migrated to an archive database while preserving cryptographic integrity:
  ```bash
  actentra archive-log receipts.db receipts_archive_2026.db --before-seq 50000 --delete-from-source
  ```
  The archival procedure operates in an atomic transaction: it verifies source integrity, migrates the exact receipt slice along with matching action envelopes, and preserves hash-chain continuity.

### 3. Dual-Layer Audit Verification
- **Hash Chain Verification:** `actentra verify-log <db_path>` validates that every receipt's `prev_hash` correctly links to the predecessor's `entry_hash` and matches its canonical payload hash.
- **Context Integrity Verification:** The `--verify-envelopes` (`-e`) flag verifies that the stored action envelopes in `action_envelopes` have not been altered or substituted after authorization by checking `SHA-256(canonicalize_json(envelope)) == decision.canonical_hash`.
- **Signed Checkpoints:** `actentra checkpoint-log <db_path> --key-file <key>` anchors the current chain head with an Ed25519 signature, providing verifiable proof against local host tampering or truncation.

### 4. Crash Recovery & Unknown Outcomes
- **Handling Interrupted Executions:** If a process crashes or loses power between an `ALLOW` decision receipt (Invariant I5) and the completion of tool dispatch, a crossing would be left without an outcome.
- **Atomic Recovery:** On startup or via `ReceiptStore.recover_pending_outcomes()`, Actentra identifies any `ALLOW` decision lacking an outcome receipt and commits an `unknown` outcome receipt (`reason="crashed_or_interrupted"`). This preserves Invariant I5 and ensures audit logs are never left in an ambiguous or half-recorded state.

### 5. Scoped Credential Resolution & Redaction
- **Platform DPAPI Storage:** The `SecretsBroker` secures credentials using Windows Data Protection API (DPAPI) tied to the local user account, falling back to AES-256-GCM on POSIX.
- **Dynamic Resolution:** Agents refer to credentials only via opaque handles (`secret:<NAME>`). Scoped executors resolve and inject these handles into HTTP headers or parameters only at the moment of dispatch.
- **Zero-Leak Redaction:** All outgoing requests, incoming response headers, bodies, error messages, and durable receipts pass through `secrets_broker.redact()`, guaranteeing that raw secrets are never leaked to logs or the agent context.

### 6. Canonical Identity & Delegation Architecture (Phase 1 / ACT-01 Hardening)
- **Four-Way Identity Separation:**
  1. *Claimed Identity:* Untrusted caller-asserted metadata (e.g. `agent_id` in request body or unverified headers).
  2. *Authenticated Identity:* Verified cryptographic or transport principal (`Bearer` token lookup, Ed25519 signature, or local process identity).
  3. *Delegated Identity:* Verified delegator principal acting through an explicit, active delegation grant.
  4. *Effective Principal:* The authorized identity under which the operation actually executes (`delegated_by` if acting under a valid delegation grant, otherwise `authenticated_identity`).
- **Bidirectional Delegation Grant Binding:**
  - A delegation grant ID alone is never sufficient for authorization.
  - The delegation registry strictly validates:
    - `grant.delegatee_id == authenticated_caller.principal_id`
    - `grant.delegator_id == caller.delegated_by`
    - `grant.audience == target_audience` (when configured)
    - Grant expiration, non-revocation, and replay nonce.
- **Scope Attenuation & Nested Depth Limits:**
  - A delegatee cannot receive scopes or represent agents that the delegator lacks.
  - Sub-delegations increment grant depth (`depth = parent.depth + 1`) bounded by `max_depth`.
  - Expirations on child grants are strictly bounded by parent grant lifetimes.
  - Revoking a parent grant cascades transitively to invalidate all downstream child grants.
- **Cryptographic Grants:**
  - Ed25519-signed delegation grants (`issue_signed_delegation_grant`, `verify_signed_delegation_grant`) allow stateless, verifiable token issuance with replay protection (`nonce`, `issued_at`, `expires_at`).
- **Canonical Security Context Propagation:**
  - `CallerContext` is consistently threaded through `Boundary`, `Gateway`, `Services`, and `Warrants`.
  - Boundary validates `ctx.is_agent_allowed(agent_id)`, `ctx.has_scope("crossings:execute")`, and ensures that any presented `Warrant.holder` matches the caller's authenticated identity or active delegator.
  - Approver identity is recorded in durable pending approval records and receipts.
