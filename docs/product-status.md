# Actentra — Product Status & Feature Matrix

**Status:** Official Reference  
**Last Updated:** 2026-11-13  

---

## 1. Feature Support Matrix

Each capability in Actentra is explicitly labeled under one of three tiers:
- **Supported:** Validated by end-to-end unit, golden, and integration tests; suitable for local development and alpha usage.
- **Experimental:** Functionally implemented with targeted tests, but operational workflow or API surface is subject to refinement.
- **Planned:** Documented architectural design or future milestone; not yet part of the enforced runtime path.

| Capability | Tier | Module | Notes & Guarantees |
| --- | --- | --- | --- |
| **Deterministic Policy Engine** | **Supported** | `actentra_core.policy` | Deny-overrides YAML evaluation, pattern matching, constraints, zero-LLM in enforcement loop. |
| **Windows Path & Resource Canonicalization** | **Supported** | `actentra_core.canonicalize` | Case normalization, UNC/device/reserved name checks, forward slashes, NFC unicode. |
| **Cryptographic Action Hash & TOCTOU Binding** | **Supported** | `actentra_core.envelope` | SHA-256 canonical hash computed and re-verified immediately before execution. |
| **Tamper-Evident Receipts Log** | **Supported** | `actentra_core.receipts` | Append-only SQLite WAL, SHA-256 hash chaining, `verify_log` audit tool. |
| **In-Process Python SDK** | **Supported** | `actentra.boundary` | `@guard` decorator, `Boundary.execute()`, fail-closed exception handling. |
| **Scoped Filesystem Executor** | **Supported** | `actentra_executors.fs` | Strict workspace containment, reparse-point defense, size & extension limits. |
| **Scoped SQLite Executor** | **Supported** | `actentra_executors.sqlite` | Single-statement check, parameter binding, read-only mode, row limits. |
| **Scoped HTTP Executor** | **Supported** | `actentra_executors.http` | SSRF defense (blocks RFC 1918 & 169.254.169.254), allowed hosts filter, size caps. |
| **MCP Stdio Proxy** | **Supported** | `actentra_gateway.mcp_proxy` | Tool call interception, tool hash pinning to detect mid-session changes (CVE-2025-54136). |
| **Cumulative Session Budgets** | **Supported** | `actentra_core.budgets` | Rate limits, call limits, write byte caps per session; updated on internal and external execution. |
| **Policy Canary Diff Engine** | **Supported** | `actentra_core.canary` | Historical receipt replay against candidate policies with temporal rate windows, provenance, and context integrity. |
| **Local HTTP Gateway & Approval UI** | **Supported** | `actentra_gateway.http_service` | Loopback-bound REST API and operator web console with strictly typed fail-closed approvals and atomic outcome recording. |
| **Persistent Pending Approvals** | **Supported** | `actentra_core.receipts` | SQLite-persisted pending approvals that survive gateway process restarts. |
| **Signed Audit Checkpoints** | **Supported** | `actentra_core.checkpoints` | Ed25519 asymmetric signatures anchoring receipt log sequence and head hash. |
| **DPAPI Secrets Broker** | **Experimental** | `actentra.secrets` | Windows DPAPI native encryption for tool secrets; automatic redaction in errors. Direct executor reference injection in progress. |
| **Cryptographic Warrants (Capability Tokens)**| **Experimental** | `actentra_core.warrants` | Standalone Ed25519-signed delegation tokens with expiration and scope verification. End-to-end Boundary authorization binding in progress. |
| **Agent Adapters (LangChain & Function Calling)** | **Supported** | `actentra.adapters` | Duck-typed tool wrappers and OpenAI/Anthropic call dictionary adapters. |
| **Enterprise Remote Control Plane / SSO** | **Planned** | — | Non-goal for V2 local-first architecture. |
| **Native Desktop Shell / Installer** | **Planned** | — | Deferred to post-beta based on user adoption. |

---

## 2. Platform Limitations & Boundaries

1. **Target Operating System:** Windows 11 (64-bit). Linux/macOS are supported in core canonicalization and execution logic, but native DPAPI secret persistence is Windows-specific.
2. **Resource Footprint:** Designed to run reliably on 8 GB RAM, Intel i5 CPU, with zero GPU or Docker requirements. Idle RSS stays under 40 MB.
3. **Execution Model:** Local-first single operator; no cloud dependencies.
