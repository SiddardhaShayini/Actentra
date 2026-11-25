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
* **Invariant I9:** Sessions are server-controlled entities cryptographically bound to authenticated principals, trust domains, policy versions, and expiration timestamps. Cross-principal session access or session ID substitution is strictly rejected. Taint is durably bound to principal identity and cannot be reset or bypassed by arbitrary session recreation.
* **Invariant I10:** Cumulative action, external call, and write byte limits are enforced across dual tiers (per-session and cumulative principal-wide). Counters are transactionally persisted in SQLite and survive process crashes, restarts, and concurrent executions.
* **Invariant I11:** Every gateway HTTP route (GET, POST, DELETE) and internal service method requires explicit scope-based authorization or trusted operator credentials. Read endpoints querying sensitive resources enforce object-level authorization and redact sensitive execution parameters for non-owners.
* **Invariant I12:** Remote gateway communication requires authenticated TLS transport (TLS 1.2+ with forward-secret ciphers). Binding to non-loopback network interfaces without TLS fails closed at startup; plaintext remote HTTP serving is strictly prohibited. Host header validation prevents DNS rebinding attacks, proxy forwarded headers are only trusted from explicitly authorized proxies, request bodies are bounded to 2 MiB (HTTP 413), and replay protection rejects duplicate nonces and excessive timestamp skew.
* **Invariant I13:** Executors enforce non-bypassable resource confinement at execution time. The SQLite executor enforces table-level authorization via the SQLite engine authorizer callback, blocking unauthorized tables across direct queries, JOINs, subqueries, CTEs, views, and triggers, and unconditionally denying ATTACH, DETACH, PRAGMA, and unauthorized DDL. The Filesystem executor enforces atomic writes via temporary-file creation and atomic replacement, verifies opened file descriptor realpaths against workspace boundaries to prevent symlink/junction/TOCTOU substitution, and validates all ancestor path components.
* **Invariant I14:** Execution integrity, postcondition binding, and external outcome claims (ACT-06, ACT-10). Callers cannot replace, weaken, or omit approved postconditions across any execution interface (Python SDK, HTTP Gateway `/v1/crossings` with `execute=True`, approved crossing execution `/v1/crossings/{id}/execute`, MCP proxy, or direct internal service APIs). An executor returning success is not proof of successful execution; success is strictly gated on independent postcondition verification. Mutating file write actions must verify expected content digests (not mere file existence). Generic strings ('verified', 'ok', 'true', 'success') are strictly rejected. Postconditions and execution parameters are cryptographically bound into an `AuthorizedExecutionContext`. External outcomes require mandatory single-use execution claims bound to the canonical action hash, authenticated principal, approval/warrant, and result digest, preventing replay, substitution, and false success promotion. Uncertain outcomes are preserved as `unknown` (never converted to success), and can be safely reconciled via independent verification (`Boundary.reconcile_outcome`).
* **Invariant I15:** External Audit Anchoring and Tamper Detection (ACT-07). SQLite WAL hash chains provide local sequence and payload integrity, but cannot prevent an attacker with database-editor access from rewriting history and recomputing SHA-256 chains. Protection against local database modification, rollback, tail truncation, or backup restoration requires independently anchored, cryptographically chained Ed25519 checkpoints stored off-host in an append-only anchor (`FileCheckpointAnchor`). Checkpoints enforce strictly monotonic sequences (`checkpoint_seq`), unique IDs, and previous-checkpoint hash references (`prev_checkpoint_hash`). Checkpoint signing keys are managed via a trusted `KeyRing` supporting cryptographic rotation and revocation; signing keys must never be stored alongside the SQLite database they protect. Independent verification (`verify_audit_trail`, `verify_audit_bundle`) cross-references local SQLite logs against external checkpoints, reporting explicit machine-readable divergences (`CHAIN_REWRITE`, `ROLLBACK`, `TAIL_TRUNCATION`, `CHECKPOINT_TAMPERING`, `SIGNATURE_FORGERY`, `UNTRUSTED_KEY`, `REVOKED_KEY`).
* **Invariant I16:** Transactional Execution Lifecycle and Durable Idempotency (ACT-09). Actions transition through an explicit, verified state machine (`created` -> `authorized` -> `approved` -> `claimed` -> `executing` -> `verification_pending` -> `succeeded` / `failed` / `unknown` / `reconciliation_required`). Any illegal or out-of-order transition is blocked with `InvalidStateTransitionError`. Idempotency keys are bound to authenticated principal identity and canonical action hash; duplicate executions of completed actions return cached results without re-dispatching side effects, conflicting parameters are rejected with `IdempotencyConflictError`, concurrent in-flight executions are blocked with `IdempotencyInFlightError`, and interrupted actions require reconciliation before replay (`ReconciliationRequiredError`). Startup crash recovery (`recover_system_state`) automatically reconciles in-flight lifecycles, expired leases, dangling claims, and unfinalized decisions to a known safe state.

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

### 3. Dual-Layer Audit Verification & External Anchoring
- **Hash Chain Verification:** `actentra verify-log <db_path>` validates that every receipt's `prev_hash` correctly links to the predecessor's `entry_hash` and matches its canonical payload hash (including `evidence_status`).
- **Context Integrity Verification:** The `--verify-envelopes` (`-e`) flag verifies that the stored action envelopes in `action_envelopes` have not been altered or substituted after authorization by checking `SHA-256(canonicalize_json(envelope)) == decision.canonical_hash`.
- **Signed Checkpoints & External Anchoring (ACT-07):** `actentra checkpoint sign <db_path> --key <key_pem> --anchor <dir>` anchors the current chain head with an Ed25519 signature in an append-only external directory, creating an unbroken checkpoint hash chain (`prev_checkpoint_hash`).
- **Audit Trail Cross-Verification:** `actentra checkpoint verify-trail <db_path> --anchor <dir> --keys <key_manifest>` independently verifies checkpoint continuity, signature authenticity, and cross-checks every external checkpoint against local SQLite receipts to detect silent chain rewrites, rollbacks, and truncations.
- **Offline Audit Bundles:** `actentra bundle export --anchor <dir> --keys <key_manifest>` exports a self-contained cryptographic audit bundle containing receipts, external checkpoints, and public key manifest for offline auditing via `actentra bundle verify`.

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

### 7. Session Isolation, Durable Budgets, Taint Integrity & Route Authorization (Phase 2 Hardening)
- **Server-Controlled Session Lifecycle:**
  - Clients can no longer choose arbitrary unauthenticated session identifiers to bypass security policies.
  - Sessions are server-issued records (`sess-<uuid>`) bound in SQLite to `principal_id`, `trust_domain`, `policy_version`, `created_at`, `expires_at`, and `status`.
  - Access to an existing session requires `sessions:read` scope and matches the session's owning principal (or trusted operator authority).
  - Attempted cross-principal session access or session ID substitution triggers `identity:cross-principal-session-access` denial tagged with `session-hijack`.
- **Durable Dual-Tier Cumulative Budgets:**
  - Session-level budgets (`max_actions`, `max_external_calls`, `max_write_bytes`) prevent runaway single-session loops.
  - Principal-level cumulative limits (`principal_max_actions`, `principal_max_external_calls`, `principal_max_write_bytes`) aggregate usage across all sessions owned by the principal.
  - Counters are durably stored in the SQLite `principal_budgets` table and survive process termination, crashes, and daemon restarts.
  - Atomic synchronization locks prevent concurrent race condition bypasses across parallel crossing requests.
- **Durable Taint Integrity & Reset Prevention:**
  - Untrusted data ingestion marks both the active session and the authenticated principal as untrusted in SQLite `principal_taints`.
  - Creating a new session inherits the principal's active taint, preventing attackers from laundering tainted contexts via session recreation.
  - Taint clearance is restricted strictly to authorized security operators (`ctx.is_trusted_operator`).
- **HTTP Route-to-Scope & Object-Level Authorization Matrix:**
  - Explicit `ROUTE_SCOPE_MATRIX` maps every GET, POST, and DELETE endpoint to mandatory permission scopes (e.g. `receipts:read`, `policies:read`, `observations:read`, `evidence:read`, `leases:read`, `handoffs:read`, `sessions:read`, `sessions:create`, `sessions:revoke`).
  - Read endpoints enforce object-level authorization: non-operator callers can only inspect pending approvals, receipts, and sessions belonging to their own identity.
  - Action parameters in pending approvals are automatically redacted (`{"_redacted": "UNAUTHORIZED_RESOURCE_ACCESS"}`) for non-owner viewers.
  - Internal `AppServices` methods replicate all route authorization checks, preventing internal direct-call bypasses.

### 8. Remote Gateway & Transport Security Architecture (Phase 3 Hardening)
- **Mandatory TLS 1.2+ Transport:**
  - Remote and private-network bindings unconditionally refuse plaintext HTTP at startup, requiring valid X.509 server certificates and private keys.
  - Forward-secret AEAD ciphers (`ECDHE+AESGCM`, `ECDHE+CHACHA20`) and TLS compression disabled (`OP_NO_COMPRESSION`).
  - Mutual TLS (mTLS) with client certificate verification against configured trusted CA bundles.
- **Anti-Replay & Nonce Tracking:**
  - Enforces sliding-window single-use nonces (`X-Actentra-Nonce`) and timestamp skew validation (`X-Actentra-Timestamp` within +/-300s).
- **Transport Hardening & Body Bounds:**
  - 2 MiB bound on HTTP request bodies (`HTTP 413 Payload Too Large`).
  - Rejection of conflicting `Transfer-Encoding` / `Content-Length` headers (HTTP request smuggling mitigation).
  - Loopback host and allowed Host header enforcement preventing DNS rebinding.

### 9. Executor Boundary Hardening (Phase 4 Hardening)
- **Filesystem Executor Isolation:**
  - Strict path canonicalization on Windows, eliminating Alternate Data Streams, 8.3 short names, and traversal tokens.
  - Open file descriptor realpath verification against workspace boundaries before read/write operations to eliminate symlink and junction TOCTOU attacks.
  - Atomic file writing via temporary file creation within workspace boundaries and atomic rename/replacement.
- **SQLite Engine Authorization:**
  - SQLite authorizer callbacks (`sqlite3.set_authorizer`) enforce table-level permissions across direct queries, JOINs, CTEs, subqueries, and triggers.
  - Unconditional blocking of `ATTACH`, `DETACH`, `PRAGMA`, and schema DDL mutations.
- **HTTP SSRF Defense:**
  - Pre-connect DNS lookup and IP validation blocking private subnets (RFC1918), loopback, and cloud metadata (`169.254.169.254`).
  - Strict redirect validation (`SSRFSafeRedirectHandler`) evaluating every redirect hop against SSRF rules.

### 10. Execution Integrity & Outcome Verification (Phase 5 & Gateway Hardening)
- **Authorized Execution Context:**
  - Binds action identity, target resource, authenticated principal, executor identity, approval identity, policy version, and required postconditions into a canonical execution context.
- **Universal Gateway & SDK Execution Integrity:**
  - `AppServices._dispatch_and_record()` enforces the same authoritative postcondition verification pipeline, execution claim binding, and lifecycle transitions as `Boundary.execute()`.
  - Eliminates the gateway bypass where `POST /v1/crossings` with `execute=True` and `POST /v1/crossings/{id}/execute` could record success merely because an executor returned without error.
  - Fail-closed semantics: actions requiring postconditions record `unknown` or `failure` if postconditions are refuted, unverified, or if no verifier is configured.
- **Policy-Mandated Postconditions:**
  - Rejection of postcondition weakening or substitution (e.g. replacing `digest_match` with generic `exists` under strict policies).
  - Unconditional rejection of ambiguous string claims (`verified`, `ok`, `true`).
- **External Outcome & Observation Binding (Phase 2 Hardening):**
  - Every crossing-bound verification (`POST /v1/observations/verify` or `AppServices.verify_state(..., crossing_id=...)`) establishes an immutable, cryptographically hashed `VerificationContext` binding `verification_id`, `crossing_id`, `canonical_action_hash`, canonical `authorized_resource`, `expected_postcondition`, `expected_digest`, `claim_id`, `executor_principal_id`, `verifier_principal_id`, `policy_version`, `observed_at`, and `expires_at`.
  - Unrelated resources, mismatched claims, mismatched digests, forged/generic claims, expired observations, and unauthorized verifiers are rejected before verification or outcome promotion.
  - External success promotion (`POST /v1/crossings/{id}/outcome` / `AppServices.record_external_outcome`) when postconditions are required atomically validates and consumes both the bound `ObservationRecord` and the one-time `ExecutionClaim` inside SQLite transactions, preventing replay and concurrent reuse.
  - Prevention of false success promotion; ambiguous outcomes preserved as `unknown`.

### 11. Immutable Audit Architecture & Checkpointing (Phase 6 Hardening)
- **Cryptographic Audit Log:**
  - Append-only SQLite WAL receipts with SHA-256 hash chaining (`prev_hash` -> `entry_hash`).
  - Dual-layer context verification checking both log hash integrity and execution context parameters.
- **Externally Anchored Ed25519 Checkpoints:**
  - Monotonic sequence numbers (`checkpoint_seq`), unique IDs, and previous-checkpoint hash chaining (`prev_checkpoint_hash`).
  - Off-host key custody with `KeyRing` rotation and revocation tracking.
  - Cross-verification tooling (`verify_audit_trail`, `verify_audit_bundle`) detecting `CHAIN_REWRITE`, `ROLLBACK`, `TAIL_TRUNCATION`, and `REVOKED_KEY`.

### 12. Production Reliability, Lifecycle State Machine & Durable Idempotency (Phase 7 & 8)
- **Action Execution Lifecycle State Machine:**
  - Transactional state machine enforcing legal transitions (`created` -> `authorized` -> `approved` -> `claimed` -> `executing` -> `verification_pending` -> `succeeded`/`failed`/`unknown`/`reconciliation_required`).
  - Immutable historical state transition audit log in `action_transitions`.
- **Durable Idempotency Engine:**
  - Primary key `(principal_id, idempotency_key)` bound to canonical action hash and tool invocation.
  - Cached result return on completed replays without tool re-dispatch.
  - `IdempotencyConflictError` on parameter tampering and `IdempotencyInFlightError` on concurrent execution.
- **Unified Startup Crash Recovery:**
  - `recover_system_state()` reconciles in-flight action lifecycles, expired leases, dangling claims, and unfinalized decisions to known safe states upon gateway or SDK initialization.
- **Observability & Operational Telemetry:**
  - `OperationalMetrics` collector tracking throughput counters, failure counts, and latency percentiles (p50, p95, p99, max).
  - Data sanitization via `sanitize_operational_data()` scrubbing secrets and tokens.
  - Exposed via `GET /v1/metrics` and `actentra metrics` CLI.
- **Agent Integration Parity:**
  - Full caller context and idempotency propagation through `MCPStdioProxy`, `FunctionCallAdapter`, and `LangChainToolWrapper`.
