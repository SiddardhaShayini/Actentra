# Deployment Guide

This guide covers deploying Actentra from local development to controlled pilots, including TLS/mTLS, principal mappings, SQLite persistence, workspace restrictions, external audit checkpoints, monitoring, and backup/recovery.

---

## 1. Deployment Modes and Security Profiles

| Profile (`SecurityProfile`) | Audit Requirements | Gateway Auth & Transport | Intended Use |
|---|---|---|---|
| `local_dev` / `local_trusted` | Local SQLite WAL hash chain (`externally_anchored: False`) | Loopback HTTP permitted | Local development and testing |
| `controlled_pilot` | `CheckpointAnchor` + active `KeyRing` required; trail verified at startup | Non-loopback/`REMOTE`/`PRIVATE_NETWORK` requires TLS 1.2+ and auth | Restricted controlled pilots |
| `external_production` | Durable, custody-separated `CheckpointAnchor` + `KeyRing` required | `require_client_cert=True`, `cert_principals`, individual `token_principals` (shared `auth_token` alone prohibited) | Hardened deployments (still subject to same-host TCB limits) |

> [!IMPORTANT]
> Per [ACTENTRA_POST_REMEDIATION_AUDIT.md](../security/audits/ACTENTRA_POST_REMEDIATION_AUDIT.md), Actentra is currently verified for **restricted controlled pilots** on Windows 11/amd64, not unconditional external production.

---

## 2. Local Development & Embedded Usage

- **Embedded Python SDK:** Instantiate `Boundary.from_files(...)` or `Boundary.from_yaml(...)` directly in your Python application. On startup, `Boundary.__init__` invokes `ReceiptStore.recover_system_state()` automatically.
- **Local Loopback Gateway:**
  ```powershell
  actentra serve --policy policies/examples/starter.yaml --workspace ./workspace --port 8080
  ```
  By default, `serve_http()` binds to `127.0.0.1:8080` and restricts CORS to loopback origins.

---

## 3. Remote Gateway Deployment, TLS, and mTLS

Binding to a non-loopback address (e.g., `0.0.0.0`) or setting `DeploymentMode.REMOTE` / `DeploymentMode.PRIVATE_NETWORK` **fails closed at startup** unless:
1. Remote binding is explicitly enabled (`--unsafe-allow-remote` / `ACTENTRA_UNSAFE_ALLOW_REMOTE=1` or non-local `deployment_mode`).
2. TLS is configured (`certfile` + `keyfile`, or `ssl_context`). `create_tls_context()` enforces TLS 1.2+, disables compression (`OP_NO_COMPRESSION`), and uses forward-secret AEAD ciphers (`ECDHE+AESGCM`, `ECDHE+CHACHA20`).
3. Authentication is configured (`token_principals` or `auth_token`).

### Principal Mappings & mTLS

For controlled pilots and `external_production`, configure individual principal mappings rather than a shared bearer token:
- **`token_principals`:** Maps each Bearer token to a `principal_id`, `principal_type`, `scopes`, `allowed_agents`, optional `expires_at`, `revoked`, `cert_fingerprint`, and `san_uri`.
- **`cert_principals` (`MTLSPrincipalRegistry`):** Maps X.509 client certificates (SHA-256 DER fingerprint, SAN URI, allowed issuers) to `CertificatePrincipalBinding`.
- When `require_client_cert=True`, `ActentraHTTPHandler` extracts the TLS socket peer certificate (`conn.getpeercert(binary_form=True)`) and verifies it matches the Bearer token principal; mismatches return `HTTP 403`. Forwarded cert headers (`X-SSL-Client-Cert`, etc.) are rejected without an authenticated TLS socket.
- Configure `allowed_hosts` (to prevent DNS rebinding) and `trusted_proxies` (only peers in `trusted_proxies` may supply `X-Forwarded-For`).

---

## 4. SQLite Persistence & Filesystem Workspace Restrictions

- **SQLite WAL:** `ReceiptStore` uses `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=15000`, and `BEGIN IMMEDIATE` transactions. Always store `receipts.db` on reliable local storage with OS file permissions restricted to the service account.
- **Workspace Confinement:** `LocalFSExecutor` and `WorkspaceFileVerifier` confine file operations to `workspace_root`. Never set `workspace_root` to `/` or `C:\` or a directory containing secrets/keys/databases. Keep `receipts.db`, policy files, and checkpoint signing keys **outside** `workspace_root`.

---

## 5. External Audit Checkpoints & Key Custody

Local SQLite hash chains (`verify_log`) do not protect against an attacker with direct write access to `receipts.db`. To detect local DB rewrites, rollbacks, and tail truncation:

1. Generate an Ed25519 keypair and keep the private key off-host or outside the SQLite DB directory:
   ```powershell
   actentra checkpoint keygen --out-dir ./keys
   ```
2. Sign periodic checkpoints to a custody-separated `FileCheckpointAnchor` directory (or remote witness mount):
   ```powershell
   actentra checkpoint sign receipts.db --key ./keys/checkpoint_private.pem --anchor ./external_anchor
   ```
3. Verify the full trail against the public `KeyRing` manifest:
   ```powershell
   actentra checkpoint verify-trail receipts.db --anchor ./external_anchor --keys ./keys/keyring.json
   ```

---

## 6. Logging, Monitoring, Backup & Recovery

- **Health & Metrics:**
  - `GET /health` returns database integrity status (`db_integrity_ok`), active `policy_version`, `frozen` state, and receipt count.
  - `GET /v1/metrics` (and `actentra metrics`) returns throughput counters, idempotency stats, and latency percentiles (`p50`, `p95`, `p99`, `max`) with secrets scrubbed via `sanitize_operational_data()`.
- **Online Hot Backup:**
  ```powershell
  sqlite3 receipts.db "VACUUM INTO 'backups/receipts_backup.db'"
  actentra verify-log backups/receipts_backup.db -e
  ```
- **Log Archival:**
  ```powershell
  actentra archive-log receipts.db receipts_archive.db --before-seq 50000 --delete-from-source
  ```
- **Crash Recovery & Reconciliation:** Startup automatically runs `recover_system_state()`. Any crossing left in `unknown` or `reconciliation_required` must be inspected (`actentra lifecycle show <crossing_id> --db receipts.db`) and resolved via `reconcile_outcome()`.

---

## 7. Controlled-Pilot Restrictions

Before running a controlled pilot, ensure all conditions from [ACTENTRA_POST_REMEDIATION_AUDIT.md](../security/audits/ACTENTRA_POST_REMEDIATION_AUDIT.md) Section 10 are met:
1. Remote mode uses TLS and mTLS/`token_principals` (prohibit unauthenticated or shared-token-only remote exposure).
2. Prohibit caller-asserted identity/delegation unless backed by registered/signed grants.
3. Use SQLite-backed durable warrants and budgets.
4. Require strict postconditions (`digest_match` / `absent`) for mutating operations and independently authorized verifiers.
5. Restrict `workspace_root` and host privileged accounts; keep checkpoint anchors and signing keys custody-separated.
6. Reconcile `unknown` outcomes rather than promoting them to `succeeded`.
7. If deploying on Linux/macOS, run a POSIX symlink race verification campaign on the target OS first.
