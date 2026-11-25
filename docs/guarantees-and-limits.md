# Guarantees and Explicit Limits

Actentra follows an **honest guarantees** model: we state clearly what the kernel enforces (verified by automated regression, adversarial, and property tests) and what lies outside its trust boundary.

---

## 1. Core Architectural Invariants (I1–I16)

Every security guarantee in Actentra corresponds directly to an enforced and tested invariant:

| ID | Invariant | Enforcement Mechanism |
| :--- | :--- | :--- |
| **I1** | **No Execution Bypass** | No code path from adapters (MCP, Function Calling, LangChain, CLI, HTTP) to executors bypasses policy evaluation. `Boundary.execute` builds an immutable `ActionEnvelope` and evaluates `PolicyEngine` before dispatching. |
| **I2** | **Fail-Closed Default** | Any error, malformed input, missing policy rule, expired lease/approval, or unavailable database fails closed. Produces `HOLD` or `DENY` and raises `ActionBlockedError` or `DatabaseUnavailableError`. |
| **I3** | **TOCTOU Action Integrity** | Canonical action hash calculated during policy evaluation must match the re-evaluated hash immediately prior to execution dispatch. Prevents parameter substitution or in-memory modification. |
| **I4** | **Strict Single-Use Approvals** | An approval grant is valid only for one exact `canonical_hash`, one `session_id`, and strictly before monotonic TTL expiry. Atomically claimed and consumed upon execution. |
| **I5** | **Pre-Commit Receipts & Outcome Tracking** | No action executes unless its decision record is durably committed to SQLite WAL; every execution attempt receives a corresponding outcome record (`success`, `failure`, `unknown`, or `reconciliation_required`). |
| **I6** | **Atomic Policy Hot-Reload** | Invalid candidate policies never replace the active policy pack. `PolicyStore.reload_*` parses and validates candidates completely before swapping active references. |
| **I7** | **Zero-Leak Secret Redaction** | Secrets managed by `SecretsBroker` never appear in plaintext in action envelopes, policy logs, receipts, or error messages. Exceptions record scrubbed labels or type names. |
| **I8** | **Bidirectional Identity & Delegation Binding** | Authenticated transport identity is separated from claimed identity. Delegation grants require bidirectional binding (`grant.delegatee_id == authenticated_caller` and `grant.delegator_id == caller.delegated_by`), scope attenuation, and nested depth limits. |
| **I9** | **Durable Cumulative Budgets & Taint Inheritance** | Action caps, write byte quotas, and external call limits are persisted in SQLite WAL and aggregated across both session and principal tiers. Security taint inherits across session creation and cannot be reset without trusted operator authorization. |
| **I10** | **Route-to-Scope & Object-Level Authorization** | Every gateway endpoint is mapped to mandatory scopes via `ROUTE_SCOPE_MATRIX`. Callers can only query and resolve approvals, receipts, and sessions belonging to their authenticated identity unless holding operator authority. |
| **I11** | **Authenticated TLS & Transport Anti-Replay** | Remote gateway bindings require TLS 1.2+ with forward-secret AEAD ciphers (refusing plaintext HTTP). Requests enforce constant-time Bearer token verification, dynamic revocation/rotation, and sliding-window replay nonces (`X-Actentra-Nonce`). |
| **I12** | **Executor Boundary Isolation & Symlink Defense** | Filesystem operations enforce opened file descriptor validation, canonical path containment, and atomic temporary-file replacement. SQLite operations enforce table-level authorization callbacks (`set_authorizer`) blocking DDL, PRAGMA, and unauthorized tables. HTTP operations enforce pre-connect and post-redirect IP checking blocking loopback, RFC1918, and link-local cloud metadata (`169.254.169.254`). |
| **I13** | **Execution Claim Binding & Outcome Integrity** | External outcomes require an authenticated `ExecutionClaim` bound to the action hash and result digest. Postcondition substitution (e.g. replacing `digest_match` with generic `exists`) is strictly rejected, and unverified results cannot be promoted to `success`. |
| **I14** | **Multi-Agent Coordination & Non-Overlapping Leases** | Shared resource access is guarded by exclusive or shared `ResourceLease` records with monotonic TTLs, active heartbeat renewal, cycle detection in task handoffs, and automatic state cleanup on expiry. |
| **I15** | **Cryptographic Audit Anchoring & Tamper Detection** | SQLite WAL receipt logs are hash-chained (`prev_hash` -> `entry_hash`). Chained Ed25519 external checkpoints anchor sequence heads to external storage, enabling independent offline verification (`verify_audit_trail`, `verify_audit_bundle`) to detect chain rewrites, rollbacks, and truncation. |
| **I16** | **Transactional Lifecycle State Machine & Durable Idempotency** | Actions transition strictly through legal state machine states (`created` -> `authorized` -> `approved` -> `claimed` -> `executing` -> `verification_pending` -> `succeeded`/`failed`/`unknown`/`reconciliation_required`). Durable idempotency records prevent replay side-effects, reject concurrent duplicates, and flag crashed operations for reconciliation. |

---

## 2. Inventory of Supported Executors

Actentra provides four first-party defended executors:

### A. LocalFSExecutor (`executors/actentra_executors/fs.py`)
- **Supported Operations:** `fs.list` (directory listing), `fs.read` (file reading), `fs.write` (atomic file writing), `fs.delete` (file removal).
- **Resource Model:** Path-based resources formatted as `path:<canonical_path>`. Canonicalized on Windows to forward slashes with drive letters and realpath resolution (`canonicalize_windows_path`).
- **Authorization Semantics:** Policy rules match resource globs (e.g. `path:C:/work/**`). File writes and deletes typically require `ASK` human approval.
- **Security Boundaries:** Strictly confined to `workspace_root`. Rejects directory traversal (`..`), Alternate Data Streams (`file.txt:stream`), Windows reserved 8.3 short names (`PROGRA~1`), device namespaces (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`), and symlinks/junctions/reparse points. On Windows, walks and holds open Win32 directory handles from `workspace_root` to the parent directory without `FILE_SHARE_DELETE` (preventing concurrent ancestor rename/junction replacement), opens targets with `FILE_FLAG_OPEN_REPARSE_POINT` to reject reparse points via `GetFileInformationByHandle`, and deletes via `SetFileInformationByHandle(FileDispositionInfo)`. On POSIX, traverses ancestors and performs all operations relative to directory file descriptors (`dir_fd`) with `O_DIRECTORY | O_NOFOLLOW` and `os.replace(..., src_dir_fd=..., dst_dir_fd=...)`.
- **Failure Behavior:** Fails closed (`ExecutorError`), catching path resolution errors, sharing violations, reparse points, permissions issues, and boundary escapes before or during OS interaction.
- **Postconditions & Evidence:** Verifies file existence or absence; computes SHA-256 digests of written contents and matches them against expected constraints (`digest_match`).
- **Known Limitations:** Does not enforce OS-level filesystem quotas (enforced at the Actentra session budget layer). On Windows, `os.replace` does not accept `dir_fd`, so confinement during atomic replacement relies on holding locked ancestor directory handles (without `FILE_SHARE_DELETE`), re-verifying directory file IDs before replacement, and inspecting the leaf with `FILE_FLAG_OPEN_REPARSE_POINT`; an adversary with kernel/admin privilege who forcibly breaks handle locks or swaps a leaf symlink in the sub-millisecond window before `MoveFileExW` is outside the local-user threat model (though `MoveFileExW`/`os.replace` replaces the link entry itself rather than following it).

### B. ScopedHTTPExecutor (`executors/actentra_executors/http.py`)
- **Supported Operations:** `http.get`, `http.post`, `http.request`.
- **Resource Model:** URL resources formatted as `https://<host>[:port]/<path>`. Canonicalized via `canonicalize_url`.
- **Authorization Semantics:** Evaluates destination URLs against allowlists, blocklists, and taint status. Untrusted sessions are strictly blocked from external network egress (`block-untrusted-egress`).
- **Security Boundaries:** Built-in SSRF defense (`SSRFSafeRedirectHandler`). Pre-resolves DNS and checks IP addresses before connection and across all redirect hops. Unconditionally blocks loopback (`127.0.0.0/8`, `::1`), RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local addresses (`169.254.0.0/16`), and cloud metadata services (`169.254.169.254`).
- **Failure Behavior:** Raises `ExecutorError` on SSRF attempts, redirect violations, or connection failures.
- **Postconditions & Evidence:** Validates HTTP status code constraints (`status_code: 200`) and response content length.
- **Known Limitations:** Dynamic public domains that resolve to private IPs post-lookup are mitigated by pre-connect IP pinning; DNS TTL cache poisoning at the OS resolver level must be managed by the host network stack.

### C. ScopedSQLiteExecutor (`executors/actentra_executors/sqlite.py`)
- **Supported Operations:** `sql.execute`, `sql.query`.
- **Resource Model:** Database URI resources formatted as `sqlite:///<path>`.
- **Authorization Semantics:** Policy rules govern read vs write verbs based on SQL AST inspection (e.g. `SELECT` vs `INSERT`/`UPDATE`/`DELETE`).
- **Security Boundaries:** Enforces single-statement SQL queries. Installs SQLite authorizer callbacks (`sqlite3.set_authorizer`) that strictly enforce allowed table access across direct queries, JOINs, CTEs, subqueries, and triggers. Unconditionally blocks `ATTACH DATABASE`, `DETACH DATABASE`, `PRAGMA`, and schema DDL modifications unless explicitly configured.
- **Failure Behavior:** Fails closed on multi-statement injection, unauthorized table access, or authorizer rejection.
- **Postconditions & Evidence:** Records modified row counts (`rows_affected`) and result hashes.
- **Known Limitations:** Complex stored procedures are not supported; SQLite only (no external database drivers in core).

### D. WorkspaceFileVerifier (`executors/actentra_executors/verifiers.py`)
- **Supported Operations:** Independent post-execution observation and state verification.
- **Resource Model:** Workspace file paths.
- **Authorization Semantics:** Read-only observation engine called by `Boundary` during postcondition verification and `ObservationVerifier`.
- **Security Boundaries:** Strictly confined to workspace root; verifies real-world disk state independently of executor claims.
- **Failure Behavior:** Raises `ObservationError` or reports `unverified` if the target state does not match expected digests.
- **Known Limitations:** Operates on local filesystem state; external remote service observations require custom evidence collectors.

---

## 3. Deliberate Non-Implementation of Arbitrary Shell Execution

Actentra intentionally **does not provide a built-in arbitrary shell execution executor** (`cmd.exe`, `powershell.exe`, `/bin/sh`, `/bin/bash` with arbitrary command strings):

- **Threat Rationale:** In AI agent systems, arbitrary shell execution is the primary vector for Remote Code Execution (RCE), prompt injection escalation, sandbox breakout, and environment variable/credential harvesting.
- **Starter Policy Posture:** Actentra's starter policy pack explicitly blocks `shell.exec` with high-risk privilege escalation tagging (`privilege-escalation-risk-deny`).
- **Mediation Posture:** In environments where external process dispatch is required, Actentra mediates tool calls via `MCPStdioProxy` (spawning downstream servers with direct argument vectors `Popen(server_cmd)`, **strictly without `shell=True`**) and function adapters that invoke explicit Python callables rather than raw shell strings.

---

## 4. Evaluation of Potential Capabilities

In accordance with Phase 8 architecture review, potential capabilities are classified as follows:

| Capability | Classification | Current Status & Architectural Rationale |
| :--- | :--- | :--- |
| **First-class Tenant Isolation** | **Enterprise** | Deferred to multi-tenant cloud control plane. Actentra currently enforces strict single-node principal and session isolation (`sess-<uuid>` bound to principal IDs). |
| **Enterprise Identity Federation (OIDC / SAML)** | **Enterprise** | Actentra currently supports cryptographic Ed25519 delegation grants and mutual TLS (mTLS) with client certificate verification. Full OIDC/SAML JWKS federation belongs in an enterprise gateway proxy. |
| **Durable Delegation Management** | **Production Reliability** | **Implemented (Phase 1).** `DelegationGrant` supports Ed25519 signing, scope attenuation, depth limits, and cascading revocation tracked in SQLite WAL. |
| **Policy Versioning & Canary Staging** | **Production Reliability** | **Implemented (Phase 1 & 2).** Policies enforce immutable version hashes (`v1:<hash>`) bound into action hashes and receipts; `run_policy_canary` detects regressions before deployment. |
| **External Executor Identity** | **Production Reliability** | **Implemented (Phase 5).** `ExecutionClaim` binds executor principal ID, crossing ID, and result digest; unauthenticated external outcome reporting is rejected. |
| **Evidence Provenance** | **Essential** | **Implemented (Phase 5 & 6).** `EvidenceRecord` binds collector identity, observation timestamps, state digests, and verification tiers into receipt logs. |
| **Schema Validation** | **Essential** | **Implemented.** Draft 2020-12 JSON schemas in `spec/` validate envelopes, policies, receipts, leases, and handoffs at runtime. |
| **Distributed Audit Aggregation** | **Enterprise** | Local hash-chained SQLite WAL receipts and exportable offline audit bundles (`verify_audit_bundle`) are supported; multi-cluster log forwarding to SIEM/lakehouses is an enterprise integration. |
| **Resource-Level Authorization** | **Essential** | **Implemented.** Full path, URL, and SQL glob matching (`path:C:/work/**`) with deny-overrides policy evaluation. |
| **Secret-Scoped Permissions** | **Essential** | **Implemented.** `SecretsBroker` decrypts DPAPI secrets at runtime, resolves `secret:<NAME>` references, and scrubs credentials from logs and error strings. |
| **Safe Operator Workflows** | **Developer Experience / Reliability** | **Implemented.** Offline Operator Console (`/ui`), approvals inbox, approval TTL expiration, atomic claim locking, and emergency freeze/unfreeze endpoints. |

---

## 5. What Actentra Cannot Do (Explicit Boundaries)

1. **Make a model correct:** Actentra enforces boundaries on tool calls; it does not prevent an LLM from reasoning poorly within allowed bounds.
2. **Protect unmediated paths:** If an agent holds direct filesystem permissions, raw API keys, or unguarded subprocess access outside Actentra, Actentra cannot mediate those calls.
3. **Defend against a fully compromised host:** If an attacker has Administrator/root control over the OS running Actentra, they can bypass in-process boundaries and alter local files. However, externally anchored checkpoints (`verify_audit_trail`) will prove that local history was tampered with or truncated.
4. **Replace OS/Cloud IAM:** Actentra complements IAM by adding deterministic per-call intent, risk, taint, and approval checks.
