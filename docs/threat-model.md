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
| T6 | **Audit log tampering, local database rewrite & historical rollback (ACT-07)** | Append-only SQLite WAL receipts with SHA-256 hash chaining (`prev_hash` -> `entry_hash`), dual-layer context verification (`actentra verify-log -e`), inclusion of all columns (`evidence_status`) in entry hashes; chained, externally anchored Ed25519 checkpoints (`FileCheckpointAnchor`) with monotonic sequences (`checkpoint_seq`), unique IDs, and previous-checkpoint hash chaining (`prev_checkpoint_hash`); off-host key custody via `KeyRing` supporting cryptographic rotation and revocation; cross-verification tooling (`verify_audit_trail`, `verify_audit_bundle`) detecting divergence (`CHAIN_REWRITE`, `ROLLBACK`, `TAIL_TRUNCATION`, `CHECKPOINT_TAMPERING`, `SIGNATURE_FORGERY`, `UNTRUSTED_KEY`, `REVOKED_KEY`) | Compromise of all external anchor destinations AND root signing keys |
| T7 | **Malicious plugin / connector** | Narrow connector scopes, strict filesystem sandboxing, and loopback-only executor dispatch | Supply-chain trust for locally installed Python dependencies in-process |
| T8 | **Policy bypass via encoding, traversal, or TOCTOU** | Canonicalize-then-hash-then-execute-same-bytes (`I3`), strict Windows path checks (ADS, reserved names, `..`, trailing dots/spaces, device namespaces) | Target parser differentials (e.g., SQL dialect quirks) |
| T9 | **Policy tampering on disk** | `policy check` validation, policy hash pinned in every receipt (`policy_version`), last-known-good reload (`I6`), OS permissions | Root/admin compromise on the host is out of scope |
| T10 | **Approval fatigue / approver spoofing** | Clear approval summary bound to `(session_id, canonical_hash)` with TTL (`I4`), atomic single-use claim on dispatch, rejection of default/empty approval | Human reviewer clicking approve without reading |
| T11 | **Capability delegation hijack / Warrant tampering & replay** | Ed25519 asymmetric signature verification, holder matching (`expected_holder=authenticated_identity` or `delegated_by`), expiration checks, tool/resource scope enforcement, and atomic quota consumption tracking in `WarrantRegistry` (`warrant:exhausted` fail-closed) | Compromise of root issuing key |
| T12 | **SSRF / Cloud metadata exfiltration & redirect bypass** | `SSRFSafeRedirectHandler` and strict URL validation in `ScopedHTTPExecutor`: scheme checking (HTTP/HTTPS only), blocking private, loopback, link-local, and cloud metadata (`169.254.169.254`) IP ranges before connect and on every redirect hop, strict max redirects limit | DNS rebinding attacks on dynamic public domains resolving to private IPs if DNS caching/pinning is not used |
| T13 | **Delegation grant hijacking & principal impersonation (ACT-01)** | Bidirectional delegation grant binding (`grant.delegatee_id == authenticated_caller` and `grant.delegator_id == delegator`), cryptographic Ed25519 verification, scope attenuation, nested depth limits (`max_depth`), transitive cascading revocation, rejection of unauthenticated caller delegation | Transport-level MITM if TLS or client credentials are not enforced at the network layer |
| T14 | **Session spoofing, budget bypass & taint reset (ACT-03)** | Server-controlled session identity (`sess-<uuid>`) bound in SQLite to authenticated principal and trust domain; cross-principal session access rejected; dual-tier durable budgets (session + principal cumulative) transactionally persisted across restarts and concurrent requests; durable principal-level taint inheritance across session recreation; operator-only taint clearance | Operator credential compromise allows authorized taint clearance |
| T15 | **HTTP route authorization gaps & sensitive parameter exposure (ACT-04)** | Explicit `ROUTE_SCOPE_MATRIX` mapping every GET/POST/DELETE route to required scopes; object-level authorization on read queries; parameter redaction (`_redacted: UNAUTHORIZED_RESOURCE_ACCESS`) for unauthorized observers; direct internal `AppServices` method authorization matching HTTP gateway checks | Overly broad role/scope assignments (`*` operator scope) |
| T16 | **Remote gateway eavesdropping, plaintext bearer token exposure, DNS rebinding & request smuggling (ACT-02)** | Mandatory authenticated TLS transport (TLS 1.2+ with forward-secret AEAD ciphers) on all non-loopback bindings; remote plaintext HTTP binding refused at startup; mutual TLS (mTLS) support with client certificate validation; constant-time Bearer token verification (`hmac.compare_digest`); dynamic token revocation (`revoke_token`) and rotation (`rotate_token`); sliding-window nonce replay protection (`X-Actentra-Nonce`) and timestamp skew validation (`X-Actentra-Timestamp`); Host header validation against allowed hosts / loopback; untrusted proxy header spoofing rejection (`X-Forwarded-For` ignored unless peer IP is in `trusted_proxies`); 2 MiB request body limit (HTTP 413); conflicting Content-Length/Transfer-Encoding smuggling checks | Zero-day vulnerability in underlying TLS stack or root CA private key compromise |
| T17 | **Executor resource escape: SQL table unauthorized access & Filesystem symlink/TOCTOU bypass (ACT-05, ACT-08)** | SQLite engine authorizer callback (`set_authorizer`) enforces table-level boundaries on direct queries, JOINs, CTEs, subqueries, views, and triggers, unconditionally blocking ATTACH, DETACH, PRAGMA, and unauthorized DDL; Filesystem executor enforces atomic writes via temporary-file creation and atomic replacement, verifies opened file descriptor realpaths against workspace boundaries to prevent symlink/junction/TOCTOU substitution, and validates all ancestor path components | Underlying kernel/filesystem bugs or driver-level reparse point bypasses |
| T18 | **Execution claim substitution, postcondition bypass & false success promotion (ACT-06)** | Cryptographic execution context binding (`AuthorizedExecutionContext`); rejection of postcondition weakening (e.g. `exists` on write rejected under strict verification, requiring `digest_match` with expected content digest); unconditional rejection of generic string claims (`verified`, `ok`, `true`); mandatory one-time `ExecutionClaim` for external outcome reporting bound to canonical hash, principal ID, approval/warrant ID, and result digest; atomic single-use claim consumption rejecting cross-principal use and replay; prevention of false success promotion when verification is unverified; preservation of uncertain outcomes as `unknown` with safe reconciliation (`Boundary.reconcile_outcome`) | Out-of-band external side effects altering state after verification window |

---

## Audit Architecture Threat Model & Protection Boundary (ACT-07)

The audit architecture formally distinguishes between eight attacker profiles and failure modes:

1. **Accidental Corruption:**
   - *Threat:* Bit flips, hardware disk sector corruption, or incomplete OS writes.
   - *Detection & Prevention:* Detected via SHA-256 hash chaining (`prev_hash` -> `entry_hash`), canonical JSON hashing, and SQLite WAL checksumming.

2. **Unauthorized Application-Level Modifications:**
   - *Threat:* Malicious or buggy application code attempting to modify, reorder, or delete committed receipts via standard APIs.
   - *Detection & Prevention:* Blocked by `ReceiptStore` append-only database constraints (`UNIQUE` index on outcome records, monotonic autoincrement sequence, read-only transaction semantics for queries).

3. **Database-Editor Access (Direct SQL Write Access):**
   - *Threat:* An attacker with direct write access to `receipts.db` modifies historical receipt fields and recomputes the SHA-256 hash chain so that `verify_log(db_path)` alone passes.
   - *Detection & Prevention:* Detected by `verify_audit_trail()`. External checkpoints signed with Ed25519 anchor past `head_seq` and `head_hash`. Because the attacker lacks the private signing key and cannot edit external append-only checkpoints, recomputed local chains trigger `CHAIN_REWRITE` divergence.

4. **Host Administrator Access:**
   - *Threat:* An OS administrator on the local host attempts to modify both SQLite databases and local filesystem files.
   - *Detection & Prevention:* Prevented by externalizing the checkpoint destination (`FileCheckpointAnchor` on an independent, append-only, or remote witness mount) and maintaining signing key custody off-host (e.g., KMS, hardware token, or remote broker). The administrator cannot modify history without triggering `CHAIN_REWRITE` or `CHECKPOINT_TAMPERING`.

5. **Full Host Compromise:**
   - *Threat:* An attacker gains total control of the execution host, capable of deleting all local files and stopping receipt emission.
   - *Protection Boundary:* Historical checkpoints already exported or transmitted to an external anchor remain cryptographically immutable and provable. The verifier detects that the host's log has ceased progressing or diverged from the external timeline. Protection is not claimed against an attacker who controls every trust anchor and remote sink simultaneously.

6. **Signing-Key Compromise:**
   - *Threat:* A private checkpoint signing key is compromised or exfiltrated.
   - *Detection & Prevention:* Mitigated by the `KeyRing` rotation and revocation manifest. The compromised key is immediately marked `revoked` with an explicit ISO 8601 revocation timestamp and rationale. Verifiers reject any checkpoints signed by that key after the revocation timestamp (`REVOKED_KEY`).

7. **Backup Rollback:**
   - *Threat:* An attacker replaces the active SQLite database with an older valid database backup snapshot, attempting to silently revert state or hide recent actions.
   - *Detection & Prevention:* Detected by `verify_audit_trail()`. External checkpoints record strictly monotonic sequence numbers (`checkpoint_seq`) and anchored receipt sequences (`head_seq`). When an older backup contains fewer records than the highest external checkpoint, the verifier flags `ROLLBACK`.

8. **Receipt Deletion and Truncation:**
   - *Threat:* An attacker deletes records from the tail or interior of the SQLite receipt table.
   - *Detection & Prevention:* Interior deletion breaks receipt sequence continuity and hash-chain linkage. Tail truncation is detected because the external checkpoint demands a higher `head_seq` than the local database provides, triggering `TAIL_TRUNCATION` / `ROLLBACK`.
