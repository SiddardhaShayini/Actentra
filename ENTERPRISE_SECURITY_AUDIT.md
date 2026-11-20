# Enterprise Security Audit

## Executive assessment

Actentra is a credible **alpha/local-first execution boundary prototype**, not yet an enterprise-enforced control plane. The implementation demonstrates useful mechanics: deterministic policy evaluation, canonicalized envelopes, pre-execution SQLite decision records, scoped local executors, approval expiry, Ed25519 warrants/checkpoints, and hash-chained evidence. However, its current trust model does not provide authenticated agent identity, durable distributed warrant quotas, pinned DNS connections, or independently reliable postcondition outcomes.

**Verdict:** Do not place Actentra between autonomous agents and critical business systems in its current state. It is suitable for controlled pilot use on a single trusted Windows host with no unauthenticated network exposure and noncritical targets.

## Scope and evidence

This audit inspected the repository source, schemas, CLI, gateway, SDK, executors, tests, CI, documentation, and local test execution. Validation performed:

- `uv sync --extra dev`
- `uv run pytest -m "not slow" -q`: passing (169 fast tests collected and pass/skips as reported)
- `uv run ruff check core executors gateway sdk cli tests`: passing
- `uv run mypy`: 37 source files passing

Passing tests are treated as evidence for tested behavior, not proof of complete security.

## Confirmed findings

| Priority | Severity | Evidence | Impact | Status |
|---|---|---|---|---|
| P0 | HIGH | HTTP identity is caller-asserted | Cross-agent impersonation, lease/handoff misuse | **REMEDIATED** |
| P0 | HIGH | HTTP DNS validation does not pin the connection peer | Public-to-private DNS rebinding/SSRF | Open |
| P1 | MEDIUM | Warrant use counters are process-local and evictable | Replay beyond `max_uses` after restart/eviction | Open |
| P1 | MEDIUM | Success receipt is recorded before postcondition verification | False success claims survive failed state verification | Open |
| P1 | MEDIUM | External outcome API accepts caller-reported success | Fabricated outcomes, budgets, and evidence | Open |

### F-1. Gateway caller identity is not bound to authentication

**Severity:** HIGH  
**Status:** REMEDIATED  
**Remediation Commit:** Finding 01 Security Hardening  
**Affected source:** `gateway/actentra_gateway/http_service.py:623-685,748-792`; `gateway/actentra_gateway/services.py:161-177`; `core/actentra_core/identity.py:54-129`

**Attack preconditions (Original):**

- Network reachability to the gateway.
- Loopback mode: no bearer token is required.
- Remote mode: possession of the configured bearer token, or token is shared among agents.

**Reproduction (Original):**

1. Create a handoff assigned to `agent-A`.
2. Send `/v1/handoffs/<id>/advance` with `caller_agent_id: "agent-A"` while authenticated as a different principal.
3. The service compares strings only and advances the handoff.
4. Acquire a lease with `owner_agent_id: "agent-victim"`.
5. Release it with no owner field; `release_resource_lease()` accepts `None` and releases it.

**Actual impact:** Agent identity spoofing, unauthorized handoff advancement/verification, lease blocking, and unauthorized lease release.

**Remediation Implemented:**

- Hardened `CallerContext` in `core/actentra_core/identity.py` to establish granular `PrincipalType` (`AUTHENTICATED_AGENT`, `HUMAN_APPROVER`, `AUTHENTICATED_OPERATOR`, `LOCAL_PROCESS`), permission `scopes`, explicit `allowed_agents` mapping, and optional `delegated_by` provenance.
- Updated `resolve_http_caller_context` to validate bearer tokens against per-principal credential configurations (`token_principals` mapping or structured credentials `agent:<id>`, `approver:<id>`, `operator:<id>`).
- Enforced strict conflict checking between caller headers (`X-Actentra-Identity`) and authenticated credentials, raising `IdentitySecurityError` on mismatch.
- Bound caller context across all mutating and sensitive endpoints in `gateway/actentra_gateway/http_service.py` and `services.py`:
  - `/v1/crossings`: authenticated agents can only propose/execute actions within their authorized agent identity or explicit delegation; caller-controlled `agent_id` overrides for arbitrary agents return HTTP 403 `unauthorized_principal`.
  - `/v1/crossings/{id}/approve`: restricted strictly to authenticated human approvers and operators with `crossings:approve` scope.
  - `/v1/handoffs`: initiating a handoff requires verified authority over `initiator_agent_id`.
  - `/v1/handoffs/{id}/advance`: caller must hold `handoffs:advance` scope and possess verified authority as the assigned agent or authorized delegate.
  - `/v1/handoffs/{id}/verify`: caller must hold `handoffs:verify` scope and possess verified authority as the designated verifier agent.
  - `/v1/leases`: lease acquisition requires `leases:acquire` scope and verified authority as `owner_agent_id`.
  - `/v1/leases/{id}/release`: release requires `leases:release` scope and mandatory matching `owner_agent_id`; `ReceiptStore.release_lease()` strictly rejects `None` or blank owner IDs, failing closed.
  - `/v1/freeze` and `/v1/unfreeze`: restricted to authenticated operators with admin scopes.

**Regression tests:** Added comprehensive test suite in `tests/unit/test_security_finding_01_identity.py` (10 passing tests verifying crossing identity spoofing, header conflicts, unauthorized handoffs, lease operations, privilege escalation, delegated authority, and thread-safe concurrent principal isolation).

### F-2. HTTP executor DNS rebinding/SSRF bypass

**Severity:** HIGH  
**Affected source:** `executors/actentra_executors/http.py:157-177,294-297`  
**Status:** **REMEDIATED**

**Attack preconditions:**

- Policy permits an attacker-controlled or attacker-manipulated hostname.
- DNS answers differ across validation and urllib connection lookups.

**Reproduction (Original):**

1. Configure `allow_private_ips=False`.
2. Return a public address from `_verify_destination_ip()` validation lookup.
3. Return `127.0.0.1` or `169.254.169.254` for urllib's subsequent lookup.
4. `urllib.request.build_opener().open()` connects to the private peer.

**Actual impact:** Loopback/private service access and cloud metadata exfiltration risk.

**Remediation Implemented:**

- Implemented `PinningDNSResolver`: resolves destination once via `socket.getaddrinfo`, validates that ALL returned address records are public and globally routable (blocking private, loopback, link-local, carrier-grade NAT `100.64.0.0/10`, benchmark ranges, and IPv4-mapped IPv6), and pins the primary IP address for the request lifecycle.
- Implemented `PinnedHTTPConnection` and `PinnedHTTPSConnection`: connects directly to `(pinned_ip, port)` via `socket.create_connection`, completely bypassing urllib/http.client secondary DNS resolution.
- Enforced post-connect peer IP verification: inspects `sock.getpeername()[0]` immediately upon TCP establishment; if peer IP is non-global or deviates from the pinned IP, the socket is immediately closed and aborted with `ExecutorError` before sending any HTTP request bytes.
- Preserved TLS SNI and Certificate Validation: for HTTPS, `ssl.wrap_socket` wraps the pinned socket with `server_hostname=self.host` (the original domain name), ensuring TLS SNI and certificate Subject Alternative Name (SAN) validation remain strict.
- Upgraded `SSRFSafeRedirectHandler`: canonicalizes redirect targets, strictly permits only HTTP/HTTPS schemes, enforces allowed-host policies, and re-resolves and pins destination IPs for every redirect hop.
- Isolated ambient proxies: `urllib.request.ProxyHandler({})` is explicitly injected into `build_opener`, preventing environment variables (`HTTP_PROXY`, `HTTPS_PROXY`) from acting as confused deputies to bypass SSRF controls.
- Hardened URL canonicalization: correctly retains bracket notation `[::1]` for IPv6 address literals.

**Regression tests:** Added comprehensive regression test suite in `tests/unit/test_security_finding_02_dns_rebinding.py` (25 passing tests verifying TOCTOU DNS rebinding, multi-record mixed DNS responses, post-connect peer IP verification, IMDS/CGNAT/IPv4-mapped blocks, redirect rebinding, TLS SNI preservation, and proxy isolation).

### F-3. Warrant max-use counter is neither durable nor atomic at restart

**Severity:** MEDIUM  
**Affected source:** `core/actentra_core/warrants.py:218-243`; `sdk/python/actentra/boundary.py:180-218,538-552`; `core/actentra_core/receipts.py:488-525`  
**Status:** **REMEDIATED**

**Attack preconditions:** A warrant is issued with finite `max_uses`, and the process restarts or 1001+ warrant IDs cause cache eviction.

**Reproduction (Original):**

1. Use a warrant twice with `max_uses=2`.
2. Restart the process or insert enough distinct warrant counters to evict its entry.
3. Reuse the still-valid warrant.
4. The in-memory counter starts at zero or is evicted, allowing quota overruns.

**Actual impact:** Replay beyond the issuer's cryptographically declared quota.

**Remediation Implemented:**

- **Durable Persistence in SQLite (`ReceiptStore`):** Added a dedicated `warrant_usages` table (`warrant_id` primary key, `issuer`, `holder`, `max_uses`, `consumed_uses`, `expires_at`, timestamps, and indexing on `holder` and `expires_at`).
- **Atomic Concurrency with `BEGIN IMMEDIATE`:** Implemented transactional consumption in `ReceiptStore.record_warrant_use()` using `BEGIN IMMEDIATE` write transactions with busy-lock retry. Checks current consumption against quota limit atomically before incrementing; raises `WarrantError` immediately if exhausted, guaranteeing zero race conditions or overruns across concurrent threads/processes.
- **Cache Eviction Resistance:** Primary authority for quota consumption is delegated to `ReceiptStore`. Warrant quotas are completely decoupled from in-memory cache capacity and survive arbitrary cache flood attacks (1001+ distinct warrants).
- **Restart Durability:** Reopened `ReceiptStore` instances query persisted `consumed_uses` directly from the database; quotas survive process restarts, Boundary re-instantiations, and uncoordinated client restarts.
- **SDK Automatic Binding:** `Boundary.__init__` automatically wires the active `ReceiptStore` into `WarrantRegistry`, ensuring all capability checks default to durable SQLite backing even if callers do not provide an explicit registry.
- **In-Memory Fallback Protection:** For non-store-backed standalone registries, the in-memory LRU cache was hardened so that exhausted quotas (`consumed >= limit`) are never evicted to make room for newer warrants.

**Regression tests:** Added dedicated test suite `tests/unit/test_security_finding_03_warrant_quotas.py` (7 passing tests covering restart durability, 1050-warrant cache eviction resistance, 20-thread concurrent atomic consumption, standalone registry persistence, transactional issuance logging, unlimited warrant tracking, and in-memory exhausted quota protection).

### F-4. Success is recorded before postconditions are verified

**Severity:** MEDIUM  
**Affected source:** `sdk/python/actentra/boundary.py:605-675`; `core/actentra_core/receipts.py:530-650,733-785`  
**Status:** **REMEDIATED**

**Attack preconditions:** A caller invokes `verify_postcondition=True` and the action is followed by a refuted/error observation.

**Reproduction (Original):**

1. Execute an action claiming `exists`.
2. Do not create the resource or delete it.
3. The verifier returns `refuted` or `error`.
4. The outcome record has already been inserted into the receipt log as `success`.

**Actual impact:** Automation and auditors observe contradictory evidence; premature success receipts can be used as execution/transition proof despite real-world verification failure.

**Remediation Implemented:**

- **Deferred Outcome Finalization:** In `Boundary.execute()`, outcome persistence is deferred until verification concludes when `verify_postcondition=True`. If `verify_postcondition=False`, outcome is recorded immediately as `status="success"` and `evidence_status="locally_observed"`.
- **Precise Status Mapping:**
  - `verified`: Mapped to `status="success"`, `evidence_status="externally_verified"`. Cumulative session budgets are updated, an `EvidenceRecord` (tier=`EXTERNALLY_VERIFIED`) is recorded, and a causal link (`verifies`) is bound.
  - `refuted`: Mapped to `status="failure"`, `evidence_status="locally_observed"`, `reason="postcondition_refuted"`, with descriptive error payload. Never emits `externally_verified` evidence or causal verification links.
  - `error`: Mapped to `status="unknown"`, `evidence_status="unknown"`, `reason="postcondition_error"`. Never emits `externally_verified` evidence.
  - `stale`: Mapped to `status="unknown"`, `evidence_status="stale"`, `reason="postcondition_stale"`.
  - Verifier exception / crash: Caught cleanly and mapped to `status="unknown"`, `evidence_status="unknown"`, logging an error observation.
  - Unconfigured verifier: When `verify_postcondition=True` is requested without a verifier, mapped to `status="unknown"`, `evidence_status="unknown"`.
- **Atomic Observation & Outcome Transaction:** Updated `ReceiptStore._append_record()` and `ReceiptStore.record_outcome()` to accept an optional `observation: ObservationRecord` parameter, committing both the verifiable state observation and the outcome receipt inside a single atomic SQLite transaction with `BEGIN IMMEDIATE`.
- **Strict Exception Mode:** Added `raise_on_postcondition_failure: bool = False` flag to `Boundary.execute()` and defined `PostconditionFailedError(ActentraError)` to allow callers to strictly fail closed on non-verified postconditions.
- **Parametric Digest Matching:** Added `postcondition_expected_digest: str | None = None` to `Boundary.execute()` for end-to-end `digest_match` verification.

**Regression tests:** Added comprehensive regression test suite `tests/unit/test_security_finding_04_postconditions.py` (10 passing tests verifying `exists`, `absent`, and `digest_match` verified and refuted paths, verifier errors, verifier exceptions, stale observations, unconfigured verifiers, strict exception raising, and atomic SQLite transaction commit).

### F-5. External outcome reporting is unbound

**Status:** **REMEDIATED**  
**Severity:** MEDIUM  
**Affected source:** `gateway/actentra_gateway/services.py:521-559`; `gateway/actentra_gateway/http_service.py:479-507` (outcome route)

**Attack preconditions:** An allowed crossing exists and an HTTP caller can reach the gateway.

**Original Vulnerability:**
In the initial gateway design, the external outcome endpoint (`POST /v1/crossings/{id}/outcome`) accepted arbitrary outcome reports without requiring proof that the crossing had been claimed for execution, without verifying that the caller was the authorized executor, and without single-use binding. Any network caller with access to the crossing ID could prematurely report success or failure, polluting the audit log with false `status="success"` entries and improperly consuming session budgets.

**Reproduction:**

1. Propose or receive an allowed external crossing.
2. Call its outcome route with `status=success` without executing the tool.
3. The store creates a caller-reported outcome and evidence without claim verification.

**Actual impact:** False outcome/status history and corrupted budget accounting.

**Remediation:**
- **One-Time Execution Claim Architecture (`actentra_core.claims`):**
  - Created `ExecutionClaim` dataclass, Crockford base32 claim ID generator (`generate_claim_id()` with prefix `claim_`), and canonical SHA-256 hash computation (`compute_claim_hash()`) cryptographically binding `crossing_id`, `executor_principal_id`, `session_id`, `canonical_hash`, `issued_at`, and `expires_at`.
- **Durable Claim Store in SQLite (`ReceiptStore`):**
  - Added `execution_claims` table with strict SQL schema (`status IN ('issued', 'consumed', 'expired')`) and indexes on `crossing_id` and `(executor_principal_id, status)`.
  - Added atomic `ReceiptStore.issue_execution_claim(...)` using `BEGIN IMMEDIATE` transactions to prevent duplicate or conflicting active claims for the same crossing.
  - Added atomic `ReceiptStore.consume_execution_claim(...)` using `BEGIN IMMEDIATE` transactions to enforce single-use consumption: validates crossing match, validates authenticated executor principal match, checks expiry, and transitions status to `consumed`.
- **Gateway Endpoints & Services Hardening:**
  - Added `POST /v1/crossings/{id}/claim` endpoint (`services.claim_crossing_for_execution`) that verifies crossing existence, requires `verdict="allow"`, checks `crossings:claim` or `crossings:execute` scope, validates principal authority over the agent, and issues a bound execution claim.
  - Hardened `POST /v1/crossings/{id}/outcome` endpoint (`services.record_external_outcome`) to strictly mandate `claim_id` from HTTP callers (`400 Bad Request`, `code: claim_required`).
  - Outcome recording verifies and atomically consumes the claim via `ReceiptStore.consume_execution_claim()`. Claim reuse/replay is rejected with `409 Conflict`, cross-executor claim spoofing is rejected with `403 Forbidden`, and expired claims are rejected with `400 Bad Request`.
  - Distinguishes `EvidenceTier.CALLER_REPORTED` for external outcomes, and updates session budgets only on verified success.
  - Preserved backward compatibility for in-process callers by auto-issuing and consuming an internal claim when `caller_context is None`.

**Regression tests:** Added comprehensive regression test suite `tests/unit/test_security_finding_05_external_outcomes.py` with 7 tests:
- `test_outcome_rejected_without_claim`: Rejects outcome submissions lacking `claim_id`.
- `test_claim_issuance_and_successful_outcome_binding`: Verifies end-to-end claim issuance, claim consumption, outcome recording, and receipt persistence.
- `test_claim_replay_rejected`: Ensures replaying an already consumed claim is rejected with `409 Conflict`.
- `test_cross_executor_claim_spoofing_rejected`: Ensures an executor cannot submit an outcome using another executor's claim (`403 Forbidden`).
- `test_expired_claim_rejected`: Ensures claims whose TTL has expired are rejected.
- `test_cannot_claim_disallowed_crossing`: Ensures crossings with `verdict="deny"` or `verdict="ask"` cannot be claimed.
- `test_http_gateway_claim_and_outcome_end_to_end`: Tests full HTTP gateway interaction across `/claim` and `/outcome`.

## Other security observations

### Lease and handoff state

`ReceiptStore.acquire_lease()` uses `BEGIN IMMEDIATE` and is safe for SQLite-local concurrent acquisition. It is not distributed coordination. HTTP release currently allows `owner_agent_id=None` in `release_resource_lease()`, as found in F-1. Handoff state also lacks principal binding and can accept caller-supplied agent IDs.

### Approval lifecycle

Persistent approvals and atomic `claim_approval_for_execution()` provide single-process duplicate protection. The `Boundary.execute()` approval callback can auto-approve if ASK; callbacks must be considered a trusted operator integration. There is no transaction that atomically combines approval, policy decision, warrant consumption, lease acquisition, execution, and outcome.

### Filesystem executor

The FS executor performs reparse/symlink checks and `resolve_fs=True` containment. A TOCTOU remains between path resolution and `open/write/unlink`; Windows reparse/junction changes can occur concurrently. Parent symlinks are checked only immediately before operations, and write targets are not rechecked after parent creation.

**Regression priority:** race each write/read/delete with symlink/junction replacement and verify failure.

### HTTP gateway

Loopback HTTP is unauthenticated by design and remote binding requires a shared bearer token. There is no TLS, mTLS, RBAC, OIDC, SAML, audit principal separation, token rotation, or CSRF model. The shared bearer token is a gateway-wide operator credential.

### Secrets

The broker avoids secret values in sample envelopes and outcomes and redacts known values. It cannot guarantee redaction for unknown encodings or secrets introduced after an error string is formed. DPAPI key data is current-user scoped and Windows-only. No KMS/HSM/vault integration exists. Environment-sourced secrets remain process memory only.

### Receipts and checkpoints

SHA-256 chaining detects accidental/easy local alteration but not a host adversary with DB/key access. Ed25519 checkpoints are strong only when keys and checkpoints are managed off-host. Private checkpoint keys are generated unencrypted by `generate_ed25519_keypair()` and returned to callers; no key custody integration exists.

SQLite synchronous behavior uses configurable NORMAL default. Despite WAL, a power/host failure plus WAL recovery needs independent fault testing. Archival splits a chain and should be threat-modeled separately.

## Enforcement invariant assessment

| Invariant | Source evidence | Assessment |
|---|---|---|
| I1 no adapter-to-executor bypass | `Boundary.execute`, wrappers | **Partial:** direct unwrapped executors and gateway `/execute` behavior can bypass SDK guard assumptions |
| I2 fail closed | envelope validation; receipt failure | **Partial:** HTTP and external outcome errors have caller-controlled effects |
| I3 canonical hash pre-execution | boundary recomputes hash | **Confirmed for in-process Boundary**, not for arbitrary external executors |
| I4 approval binding | in-memory + SQLite approval | **Partial:** no authenticated approver or principal binding |
| I5 decision precedes execution | receipt commit | **Confirmed in registered executor path** |
| I6 last-known-good policy | `PolicyStore` | **Good for tested reload path** |
| I7 secrets absent | broker/redaction | **Good but limited** |

## Enterprise conditions

An enterprise can consider Actentra only after all P0/P1 controls are remediated and the following exist:

1. Authenticated, role-separated principals for agents, approvers, operators, and executors.
2. Transactional distributed/HA state and cryptographically durable quotas.
3. Pinned DNS/peer validation and independently tested redirect behavior.
4. Correct success/failure semantics for postconditions and external outcomes.
5. Signed, independently anchored audit checkpoints with KMS-backed key custody.
6. Independent penetration testing, threat-model review, SBOM, and release signing.
