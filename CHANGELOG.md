# Changelog

All notable changes to Actentra are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project currently tracks pre-1.0 development (`0.1.0a0` in `pyproject.toml`).

## [Unreleased]

### Documentation & Release Readiness
- Added [ACTENTRA_SECURITY_MODEL.md](ACTENTRA_SECURITY_MODEL.md), [ACTENTRA_RELEASE_READINESS_REPORT.md](ACTENTRA_RELEASE_READINESS_REPORT.md), and the complete documentation hub under [docs/README.md](docs/README.md).
- Enhanced [README.md](README.md) with verified local CPU (Ollama) and Kaggle 2x T4 GPU multi-model enforcement results, PyPI-safe image URLs, and explicit platform/security scope.

### Examples & Cross-Platform Fixes (Post-`0.1.0a0`)
- Added real-world AI-agent enforcement demo (`examples/real_agent_demo/`) and Kaggle multi-model notebook (`00f12c1`..`ed230bc`).
- Fixed POSIX root path handling in `core`, `executors`, and `sdk` (`8aec173`).

## [0.1.0a0] - 2026-11-26

First alpha release published to PyPI (`actentra==0.1.0a0`, commit `2c0357f`) via GitHub Actions Trusted Publishing.

### Developer Usability & SDK Ergonomics
- Unified public SDK exports in `actentra` (`Boundary`, `ExecutionResult`, `CrossingReceipt`, `path_resource`, `load_policy_file`, `load_policy_yaml`, `ReceiptStore`, `Decision`, `Verdict`, `ProvenanceItem`, `CanonicalizationError`, scoped executors, and `WorkspaceFileVerifier`).
- Added `Boundary.from_yaml(...)`, `workspace_root=` convenience initialization on `Boundary.from_files(...)` / `Boundary.from_yaml(...)`, executor registration helpers (`register_fs`, `register_sqlite`, `register_http`, `register_executor`), `Boundary.run(...) -> ExecutionResult`, and receipt inspection helpers (`inspect_crossing`, `recent_receipts`, `verify_receipts`).
- Added optional `--workspace / -w` flag to `actentra init` to generate starter policies scoped to a workspace directory.
- Aligned `actentra_core.context._canonicalize_value` string newline handling (`allow_newlines=True`) with `actentra_core.envelope._canonicalize_params` so multi-line `fs.write` payloads verify cleanly under `AuthorizedExecutionContext`.
- Added runnable examples (`examples/minimal_file_write.py`, `examples/minimal_blocked_action.py`, `examples/gateway_http_example.py`, `examples/agent_function_calling.py`), updated [docs/guides/quickstart.md](docs/guides/quickstart.md), and added [docs/guides/developer-usability-report.md](docs/guides/developer-usability-report.md).

### Documentation
- Reorganized repository documentation under `docs/architecture/`, `docs/security/` (including `audits/` and `remediations/`), `docs/guides/`, and `docs/development/`.
- Preserved historical security audit reports and remediation evidence, including `ACTENTRA_POST_REMEDIATION_AUDIT.md`.
- Removed superseded implementation plans, agent memory logs, and outdated pre-hardening snapshots.
- Added `CONTRIBUTING.md` and `CHANGELOG.md`.

### Security & Hardening (Phases 1–5 & ACT-01..ACT-10)
- **Deployment Security Profiles & External Audit Anchoring:** Enforced `SecurityProfile` (`local_dev`, `controlled_pilot`, `external_production`), `FileCheckpointAnchor`, `KeyRing` rotation/revocation, and `verify_audit_trail` / `verify_audit_bundle` cross-verification (`85b663a`, `e21f8b5`).
- **mTLS & Principal Binding:** Bound X.509 client certificates (`MTLSPrincipalRegistry`) to application principals in `resolve_http_caller_context()` and `ActentraHTTPHandler`, rejecting identity mismatches with HTTP 403 (`9d54fb0`).
- **Race-Resistant Filesystem Confinement:** Implemented handle-relative ancestor traversal on Windows (`CreateFileW` / `FILE_FLAG_OPEN_REPARSE_POINT`) and `dir_fd`-relative `openat`-style operations on POSIX (`6eacb68`, `94e43d3`).
- **Canonical Verification Context & Execution Integrity:** Bound postcondition verification (`VerificationContext`), `ExecutionClaim` single-use consumption, and `AppServices._dispatch_and_record()` verification parity with `Boundary.execute()` (`be6a3eb`, `7e3ae2a`, `deddded`).
- **Authenticated TLS & Gateway Protections:** Enforced TLS 1.2+ with forward-secret AEAD ciphers on non-loopback bindings, replay nonce/timestamp checks, 2 MiB body limits, and request-smuggling protections (`b5f5c2e`).
- **Session Isolation, Durable Budgets & Route Authorization:** Added server-issued sessions (`sess-<uuid>`), durable SQLite `principal_budgets` and `principal_taints`, and `ROUTE_SCOPE_MATRIX` with object-level authorization (`d7820ef`).
- **Identity & Delegation Hardening:** Separated claimed vs. authenticated vs. delegated identity, added `DelegationRegistry` with scope attenuation and depth limits, and removed unauthenticated structured bearer-token bypasses (`c650c66`, `20a2347`).
- **Warrant Quota & SSRF Remediations:** Persisted finite-use warrant quotas in SQLite `warrant_usages` with fail-closed in-memory saturation (`1a72f58`), and added DNS-pinning + post-connect peer verification in `ScopedHTTPExecutor`.

### Reliability & Core Capabilities (Phases 7–8)
- **Action Lifecycle State Machine & Durable Idempotency:** Added explicit transactional state transitions (`action_transitions`), `(principal_id, idempotency_key)` deduplication, and `recover_system_state()` startup crash recovery (`9ab4541`).
- **Observability & Adapter Parity:** Added `OperationalMetrics` (`GET /v1/metrics`, `actentra metrics`) with secret scrubbing, and full caller context / idempotency propagation across `MCPStdioProxy`, `FunctionCallAdapter`, and `LangChainToolWrapper` (`e6beef7`).
