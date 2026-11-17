# Actentra — Product Status & Feature Matrix

**Status:** Official Reference  
**Last Updated:** 2026-11-17  

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
| **Tamper-Evident Receipts Log** | **Supported** | `actentra_core.receipts` | Append-only SQLite WAL, SHA-256 hash chaining, bounded streaming `verify_log` audit tool. |
| **Bounded Streaming Audit & Archival** | **Supported** | `actentra_core.receipts` | Streaming cursor iteration (`iter_records_stream`), chunked export, $O(1)$ memory verification, and safe DB archival (`archive_records`). |
| **In-Process Python SDK** | **Supported** | `actentra.boundary` | `@guard` decorator, `Boundary.execute()`, fail-closed exception handling, warrant verification. |
| **Scoped Filesystem Executor** | **Supported** | `actentra_executors.fs` | Strict workspace containment, reparse-point defense, size & extension limits. |
| **Scoped SQLite Executor** | **Supported** | `actentra_executors.sqlite` | Single-statement check, parameter binding, read-only mode, row limits. |
| **Scoped HTTP Executor** | **Supported** | `actentra_executors.http` | SSRF defense (blocks RFC 1918 & 169.254.169.254), allowed hosts filter, credential reference injection, redaction. |
| **MCP Stdio Proxy** | **Supported** | `actentra_gateway.mcp_proxy` | Tool call interception, tool hash pinning to detect mid-session changes (CVE-2025-54136). |
| **Cumulative Session Budgets** | **Supported** | `actentra_core.budgets`<br>`actentra_core.receipts` | Rate limits, call limits, write byte caps per session; durable cumulative counters persisted across process restarts via SQLite `session_budgets`. |
| **Durable Session Taints** | **Supported** | `actentra_core.receipts`<br>`actentra.boundary` | Session taint tracking (`trusted`, `untrusted`, `unknown`) persisted across process restarts via SQLite `session_taints`. |
| **Evidence Quality Taxonomy** | **Supported** | `actentra_core.evidence`<br>`actentra_core.receipts` | 5-tier evidence model (`locally_observed`, `caller_reported`, `externally_verified`, `stale`, `unknown`), JSON schema draft 2020-12, SHA-256 evidence hash. |
| **Identity & Principal Boundaries** | **Supported** | `actentra_core.identity`<br>`actentra_gateway.services` | `PrincipalType` and `CallerContext` enforcement; rejects unauthenticated callers claiming reserved system/admin IDs or self-declared `trusted` provenance. |
| **Policy Canary Diff Engine** | **Supported** | `actentra_core.canary` | Historical receipt replay against candidate policies with temporal rate windows, provenance, and context integrity. |
| **Local HTTP Gateway & Approval UI** | **Supported** | `actentra_gateway.http_service` | Loopback-bound REST API and operator web console with strictly typed fail-closed approvals, atomic outcome recording, and interactive policy wizard. |
| **Persistent Pending Approvals & Restart Safety** | **Supported** | `actentra_core.receipts`<br>`actentra_gateway.services` | SQLite-persisted pending and approved records that survive gateway process restarts and execute through scoped executors with atomic claim deduplication. Verified via `actentra demo-gateway`. |
| **Signed Audit Checkpoints** | **Supported** | `actentra_core.checkpoints` | Ed25519 asymmetric signatures anchoring receipt log sequence and head hash against local rewrite. |
| **DPAPI Secrets Broker** | **Supported** | `actentra.secrets` | Windows DPAPI native encryption for tool secrets; dynamic executor credential reference resolution (`secret:<NAME>`) and zero-leak redaction. |
| **Cryptographic Warrants (Capability Tokens)**| **Supported** | `actentra_core.warrants` | Ed25519-signed capability delegation tokens with holder, expiry, and scope validation; end-to-end SDK `Boundary` authorization binding and use quota tracking. |
| **Agent Adapters (LangChain & Function Calling)** | **Supported** | `actentra.adapters` | Duck-typed tool wrappers and OpenAI/Anthropic call dictionary adapters. |
| **Restart-Safe Gateway Demo** | **Supported** | `actentra_gateway.demo` | Automated demonstration of allowed read, ASK delete, pending restart, approval grant, approved restart, execution, and verification (`actentra demo-gateway`). |
| **Verifiable World State Observation** | **Supported** | `actentra_core.observations`<br>`actentra_executors.verifiers` | Additive read-only verifier for workspace file state, hash-chained records in SQLite, freshness bounds, REST/CLI inspection. |
| **Causal Graph / Reference Trace** | **Supported** | `actentra_core.causal`<br>`actentra_core.receipts` | Typed directional relationships, DAG cycle detection, timeline reconstruction, and REST/CLI trace inspection. |
| **Cross-Agent Task Continuity & Handoffs** | **Supported** | `actentra_core.handoffs`<br>`actentra_gateway.services` | Scope-limited task handoffs across agent boundaries with assertion claims, causal DAG linkage, independent verification, and drift contradiction detection (`actentra handoff`, `actentra demo-handoff`). |
| **Multi-Agent Resource Leases & Coordination** | **Supported** | `actentra_core.coordination`<br>`actentra_gateway.services`<br>`actentra.boundary` | Durable resource leases with exclusive/shared locking modes, wildcard resource patterns, fail-closed mutation conflict detection, and REST/CLI/SDK interfaces (`actentra lease`). |
| **Real-Time Multi-Agent Concurrency Simulation** | **Supported** | `actentra_gateway.multi_agent_realtime_sim`<br>`actentra_cli.main` | Live multi-agent stress test running 4 concurrent autonomous agent threads (`ingest`, `transform`, `auditor`, `adversary`) against shared workspace and SQLite WAL; verifies conflict prevention, postconditions, and unbroken hash chain (`actentra demo-realtime`). |
| **Automatic Postcondition Verification** | **Supported** | `actentra.boundary`<br>`actentra_executors.verifiers` | Seamless execution postcondition checking (`verify_postcondition=True`) linking ground-truth file digests, `externally_verified` evidence, and causal trace DAG references. |
| **Enterprise Remote Control Plane / SSO** | **Planned** | — | Non-goal for local-first architecture. |
| **Native Desktop Shell / Installer** | **Planned** | — | Deferred to post-beta based on user adoption. |

---

## 2. Invariant-to-Test Evidence Matrix

Every claimed core guarantee and invariant is directly verified by automated tests in the test suite:

| Invariant / Guarantee | Core Contract | Primary Test Suites | Verified Behaviors |
| --- | --- | --- | --- |
| **I1: No bypass of policy** | Every action must pass policy evaluation | `tests/golden/test_golden_sdk_cli.py`<br>`tests/unit/test_adapters.py` | `Boundary.execute()` and `@guard` cannot invoke target function without evaluated verdict. |
| **I2: Fail-closed on errors** | Invalid envelope or storage failure blocks execution | `tests/golden/test_golden_sdk_cli.py`<br>`tests/unit/test_security_review_remediations.py` | Malformed paths, bad types, or DB commit errors raise `ActionBlockedError` with `HOLD`/`DENY`. |
| **I3: Pre-exec TOCTOU verification** | Action hash recomputed immediately before execution | `tests/chaos/test_chaos.py`<br>`tests/golden/test_golden_sdk_cli.py` | Mutating action payload between evaluation and execution causes immediate `ActionBlockedError(rule_id="kernel:hash-mismatch")`. |
| **I4: One-time hash-bound approval** | Approval grants expire, key on `(session, hash)`, single-use | `tests/golden/test_golden_sdk_cli.py`<br>`tests/unit/test_app_services.py`<br>`tests/unit/test_gateway_demo.py` | Different hash/session rejected; approval consumed on use; concurrent claims dispatch at most once; survives process recreation. |
| **I5: Durable receipts precede execution** | Decision committed to WAL before execution; outcome recorded | `tests/unit/test_receipts.py`<br>`tests/unit/test_receipt_archival.py`<br>`tests/unit/test_gateway_demo.py` | Decision receipt exists in DB before executor runs; external execution recorded with `reported_by: "caller"`. |
| **I6: Safe policy reloads** | Malformed candidate YAML never replaces active policy | `tests/unit/test_policy.py`<br>`tests/unit/test_security_review_remediations.py` | Invalid syntax, missing defaults, or non-fail-closed verdicts abort reload, leaving active engine untouched. |
| **I7: Zero credential leakage** | Raw secrets never appear in envelopes, receipts, errors | `tests/unit/test_secrets_broker.py`<br>`tests/unit/test_http_executor.py` | `SecretsBroker.redact()` replaces secrets with `[REDACTED]` across response bodies, headers, errors, and receipts. |
| **Warrants: Delegation tokens** | Ed25519 signed capability scope & quota enforcement | `tests/unit/test_warrants.py` | Validated holder, expiry, tool/resource scope, signature, and `max_uses` quota exhaustion. |
| **SSRF: Safe HTTP client** | Blocks private/cloud metadata IPs and unsafe redirects | `tests/unit/test_http_executor.py` | Rejects `169.254.169.254`, loopback, private ranges, credentials in URLs, and redirect loops. |
| **FS: Reparse & symlink defense** | Strict workspace containment without junction escapes | `tests/unit/test_fs_executor.py`<br>`tests/chaos/test_chaos.py` | Directory traversal, ADS (`:stream`), and reparse-point escapes fail closed. |
| **Canary: Replay fidelity** | Replays historical actions preserving timing & budgets | `tests/unit/test_canary.py` | Accurately tests candidate policies against real history without artificial rate-limit spikes. |
| **Audit: Streaming & archival** | $O(1)$ memory streaming log verification and DB archival | `tests/unit/test_receipt_archival.py`<br>`tests/golden/test_golden_sdk_cli.py` | Verifies large receipt logs without memory spikes; archives historical records to standalone databases. |
| **Gateway: Restart-safe approvals** | Approved crossings in SQLite execute after restart with atomic claim | `tests/unit/test_app_services.py`<br>`tests/unit/test_gateway_demo.py` | Approvals in SQLite survive restart; unexecuted approved crossings execute in new process; double-dispatch rejected. |
| **Observations: Verifiable state** | Read-only verifier captures subject digest, claim, trust domain, and freshness | `tests/unit/test_observations.py` | Verifies workspace file claims (exists, absent, digest_match), bounds freshness, chains observation hash, fails closed outside workspace. |
| **Causal Trace: Provenance DAG** | Typed references link proposals, decisions, approvals, outcomes, and observations | `tests/unit/test_causal_trace.py` | Verifies acyclic DAG integrity, detects cycles, reconstructs chronological and causal role timeline, exposes REST and CLI trace inspection. |
| **Handoffs: Cross-agent continuity** | Scope-restricted handoffs with independent verification and drift contradiction detection | `tests/unit/test_handoffs.py` | Enforces caller identity authorization, verb/resource bounds, independent third-party verification of state assertions, catches out-of-band drift, and persists through process restarts. |
| **Evidence: Quality taxonomy** | Tiered outcome evidence (`locally_observed`, `caller_reported`, `externally_verified`, `stale`, `unknown`) with hash-binding | `tests/unit/test_evidence.py` | Validates schema conformance, hash determinism, freshness expiration, and tier labeling across internal and external executions. |
| **Identity: Principal boundaries** | Anti-spoofing validation for caller principals and self-declared provenance | `tests/unit/test_evidence.py` | Rejects unauthenticated callers asserting system/admin IDs or `trusted` provenance; admits authenticated operators and local callers. |
| **Durable State: Budgets & Taint** | Cumulative action counts, external calls, write bytes, and taint levels persist across restarts | `tests/unit/test_evidence.py` | Proves budget caps and session taint survive process termination and engine reconstruction without state loss. |
| **Coordination: Resource Leases** | Conflict-locking for multi-agent shared resource mutations and postconditions | `tests/unit/test_coordination.py` | Enforces exclusive and shared lease locks, rejects conflicting concurrent mutating operations, auto-verifies postconditions, and links causal verification traces. |
| **Real-Time Concurrency: Active Multi-Agent Stress** | Concurrently running autonomous agents against shared boundary and WAL | `tests/unit/test_realtime_multiagent.py` | 4 simultaneous agent threads executing writes, reads, audits, adversary attempts; verified zero DB lock contention, conflict prevention, adversary containment, and unbroken WAL hash chain. |

---

## 3. Platform Limitations & Trust Boundaries

1. **Target Operating System:** Windows 11 (64-bit). Linux/macOS are supported in core canonicalization and execution logic, but native DPAPI secret persistence is Windows-specific.
2. **Resource Footprint:** Designed to run reliably on 8 GB RAM, Intel i5 CPU, with zero GPU or Docker requirements. Idle RSS stays under 40 MB.
3. **Execution Model:** Local-first single operator; no cloud dependencies.
4. **State Persistence vs. Process-Local Bounds:** SQLite WAL persists receipts, envelopes, pending/approved records, session cumulative budgets, session taint levels, typed evidence records, and resource leases. Rate limit token buckets, warrants in-memory use-counters, and emergency freeze state remain process-local.
5. **Caller-Asserted vs. Verified Evidence:** Gateway caller identity (`session_id`, `agent_id`, `provenance`) is validated against caller context. External outcomes are labeled `caller_reported` with distinct evidential status and do not constitute independent ground-truth proof.
6. **Local Tamper Evidence:** SHA-256 hash chains detect accidental or uncoordinated edits to the SQLite DB; they do not defend against a host root administrator unless anchored to independently stored Ed25519 checkpoints.
