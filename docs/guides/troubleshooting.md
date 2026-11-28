# Troubleshooting Guide

This guide covers common errors encountered when installing, configuring, and operating Actentra, along with exact diagnostic steps.

---

## 1. Installation & Import Errors

### `Requires-Python >=3.12` error
Actentra uses Python 3.12+ features (`StrEnum`, modern typing, `UTC`). Check your active interpreter:
```powershell
python --version
```
If using `uv`, pin Python 3.12+:
```powershell
uv python install 3.12
uv sync --extra dev
```

### `ModuleNotFoundError: No module named 'actentra'`
Ensure you are running inside the virtual environment where Actentra is installed, or run via `uv run`:
```powershell
uv run python -c "from actentra import Boundary; print(Boundary)"
```

---

## 2. Authentication Failures (`IdentitySecurityError`, HTTP `401` / `403`)

- **`Invalid or unauthorized bearer token` (`401`):**
  - Cause: Missing `Authorization: Bearer <token>` header, or the token does not match `auth_token` / `token_principals`.
  - Fix: Verify the configured token or `ACTENTRA_GATEWAY_TOKEN`. Structured tokens like `Bearer operator:attacker` are rejected whenever server authentication is configured.
- **`mTLS identity binding mismatch` (`403`):**
  - Cause: The X.509 client certificate principal in `MTLSPrincipalRegistry` does not match the Bearer token principal, or the certificate fingerprint/SAN URI does not match `token_principals`.
  - Fix: Ensure the client presents a certificate and Bearer token belonging to the same `principal_id`.
- **`Mutual TLS client certificate required`:**
  - Cause: `require_client_cert=True` (mandatory for `SecurityProfile.EXTERNAL_PRODUCTION`), but no valid client cert was presented on the TLS socket. Forwarded headers (`X-SSL-Client-Cert`, etc.) are rejected without an authenticated TLS socket.
- **`Replay detected` / timestamp skew error:**
  - Cause: Duplicate `X-Actentra-Nonce` or `X-Actentra-Timestamp` outside `+/-300s`.
  - Fix: Generate a fresh nonce per request and synchronize host clocks (NTP).

---

## 3. Authorization Denials (`ActionBlockedError`)

`ActionBlockedError` is raised when policy evaluates to `DENY`, `HOLD`, or an unapproved `ASK`.

- **Default deny (`rule_id="default-deny"`):** No rule matched `(tool, verb, resource)`. Check that `resource` uses canonical `path:...` formatting via `path_resource(path, workspace_root=workspace)` and matches your YAML glob (e.g., `path:C:/work/**`).
- **Session or principal taint (`untrusted-provenance` / `block-untrusted-egress`):**
  - Cause: A prior action ingested `ProvenanceItem(..., trust="untrusted")`, tainting the session and principal in SQLite `principal_taints`. Creating a new session inherits principal taint.
  - Fix: Only an authorized operator (`ctx.is_trusted_operator`) can clear principal taint; untrusted sessions cannot perform restricted egress.
- **Unapproved `ASK`:**
  - Cause: No `approval_callback` was provided (in-process), or the pending approval in the gateway `/ui` console was not approved before TTL expiry.
  - Fix: Pass `approval_callback=cli_approval_prompt` (or a custom callback) in SDK mode, or approve the crossing in `GET /ui` / `actentra approvals resolve`.
- **Budget or rate-limit exceeded:**
  - Cause: `session_budgets`, `principal_budgets`, or `RateLimiter` limits reached. Inspect `boundary.recent_receipts()` or `GET /v1/metrics`.

---

## 4. Canonicalization & Executor Errors

- **`CanonicalizationError`:** Raised for path traversal (`..`), Windows Alternate Data Streams (`file.txt:stream`), 8.3 short names (`PROGRA~1`), reserved device names (`CON`, `NUL`, `COM1`), or non-HTTP(S) / credential-embedded URLs. Pass clean paths relative to `workspace_root` via `path_resource()`.
- **`ExecutorError` (Filesystem):** Raised if a path escapes `workspace_root`, hits a symlink/junction/reparse point, or encounters a concurrent directory modification.
- **`ExecutorError` (HTTP SSRF):** Raised if a URL or redirect hop resolves to loopback (`127.0.0.0/8`, `::1`), RFC1918 private IPs, or link-local/cloud metadata (`169.254.169.254`).
- **`ExecutorError` (SQLite):** Raised on multi-statement SQL, comments (`--`, `/*`), `ATTACH`/`DETACH`/`PRAGMA`, DDL, or tables not in the allowlist.

---

## 5. Postcondition Failures (`PostconditionFailedError`, `ContextError`)

- **`Weak postcondition rejected` (`ContextError`):** Under strict verification (`strict=True`), mutating `write` operations cannot use `claim="exists"`; they require `claim="digest_match"` with an expected SHA-256 digest (auto-derived from `params["content"]` when present). Generic claims (`"verified"`, `"ok"`, `"true"`) are always rejected.
- **`PostconditionFailedError`:** Raised when `raise_on_postcondition_failure=True` and the verifier returns `refuted`, `error`, or `unknown` (e.g., file was not written, digest mismatched, or no verifier was configured).

---

## 6. Unknown Outcomes, Crash Recovery & Reconciliation

- **Why is a crossing in `unknown` or `reconciliation_required`?**
  - The process crashed mid-execution, a required verifier was unavailable, or an observation expired (`stale`). Actentra **never** promotes unverified outcomes to `succeeded`.
- **How to inspect and reconcile:**
  1. Inspect lifecycle and transitions:
     ```powershell
     actentra lifecycle show <crossing_id> --db receipts.db
     actentra lifecycle transitions <crossing_id> --db receipts.db
     ```
  2. Verify the actual target state (e.g., via `WorkspaceFileVerifier` or `boundary.verify_state(...)`) and call `boundary.reconcile_outcome(crossing_id, observation=verified_obs)` (or `AppServices.reconcile_outcome(...)`).
- **`DatabaseUnavailableError`:**
  - Cause: SQLite receipt database is missing, locked beyond `busy_timeout`, or failed `validate_database_integrity()` (`PRAGMA quick_check`, sequence gap, or hash-chain mismatch).
  - Fix: Run `actentra verify-log receipts.db -e`. If corrupted, restore from a verified backup (`VACUUM INTO`) and cross-check against external checkpoints via `actentra checkpoint verify-trail`.
