# Actentra Current State

## Executive summary

Actentra is not a broad AI platform yet. It is a substantial local-first Python toolkit that already implements a deterministic execution boundary for agent tool use: canonicalizing proposed actions, assigning risk tags, evaluating deny-by-default YAML policies, supporting approval workflows, dispatching through scoped executors, and writing tamper-evident receipts.

The clearest current reality is this:

- It has a credible core for action authorization.
- It has a useful local operator surface and SDK integration model.
- It does not yet have a verified, durable representation of external reality.
- It remains a prototype for controlled execution and evidence capture, not a fully trustworthy autonomous-control platform.

## Evidence from the repository

### Implemented and tested or strongly exercised

| Capability | Evidence | Assessment |
|---|---|---|
| Deterministic policy and risk engine | [`core/actentra_core/policy.py`](core/actentra_core/policy.py), [`core/actentra_core/risk.py`](core/actentra_core/risk.py), [`core/actentra_core/budgets.py`](core/actentra_core/budgets.py) | Implemented and integrated with the policy lifecycle. |
| Action canonicalization and hashing | [`core/actentra_core/canonicalize.py`](core/actentra_core/canonicalize.py), [`core/actentra_core/envelope.py`](core/actentra_core/envelope.py), [`spec/canonical_test_vectors.json`](spec/canonical_test_vectors.json) | Strong implementation for deterministic action identity. |
| Receipt storage and audit chain | [`core/actentra_core/receipts.py`](core/actentra_core/receipts.py) | Durable local evidence store exists with hash chaining, approvals, and queries. |
| CLI and SDK integration | [`cli/actentra_cli/main.py`](cli/actentra_cli/main.py), [`sdk/python/actentra/boundary.py`](sdk/python/actentra/boundary.py) | High usability for developers; the SDK is a major project strength. |
| Scoped executors | [`executors/actentra_executors/fs.py`](executors/actentra_executors/fs.py), [`executors/actentra_executors/sqlite.py`](executors/actentra_executors/sqlite.py), [`executors/actentra_executors/http.py`](executors/actentra_executors/http.py) | First-party resource controls exist and are meaningful. |
| MCP and gateway flow | [`gateway/actentra_gateway/mcp_proxy.py`](gateway/actentra_gateway/mcp_proxy.py), [`gateway/actentra_gateway/http_service.py`](gateway/actentra_gateway/http_service.py), [`gateway/actentra_gateway/services.py`](gateway/actentra_gateway/services.py) | Local gateway and operator console are implemented. |
| Policy tooling and replay | [`core/actentra_core/canary.py`](core/actentra_core/canary.py), [`corpus/`](corpus/) | Canary and replay are present, but they are advisory and not yet fully faithful as a production release gate. |
| Documentation and contracts | [`README.md`](README.md), [`docs/lifecycle-contract.md`](docs/lifecycle-contract.md), [`docs/product-status.md`](docs/product-status.md) | Good project-level narrative and normative lifecycle docs exist. |

### Implemented but not yet fully trustworthy in production terms

- Approval persistence is durable in SQLite, but process-local state such as budgets, taint, and rate-limit buckets still need explicit restart semantics.
- The gateway accepts caller-supplied identity-like fields such as `session_id`, `agent_id`, and provenance; these are useful for local dev but are not an authenticated principal model.
- The audit log is local tamper evidence, not independent proof of a real external effect.
- Warrant and secrets flows exist as primitives but are not yet clearly proven end-to-end in the same way as the core policy path.

### Partially implemented or experimental

- Verifiable external world-state: not implemented as a durable, fresh, independently verified source of truth.
- Cross-agent continuity: prototype implemented with signed handoff objects (see `core/actentra_core/handoffs.py`).
- Causal execution graph: present as an idea, not a fully modeled or enforced feature.
- Multi-tenant remote control plane: not yet a justified production posture; local-first is the current support boundary.

### Missing or unclear

- Independent evidence for real-world state transitions beyond the local system boundary.
- Strong authenticated identity and trust boundaries across remote callers.
- A single authoritative model of provenance, freshness, and uncertainty.
- A production policy for retention, secret redaction, and long-lived audit bundles.

## Current maturity assessment

### Best classification

Actentra is best described as a feature-rich alpha prototype with a strong deterministic core and a promising local-first execution boundary, but not yet as a mature general-purpose agent-infrastructure platform.

### Actual guarantees

The repository supports these concrete claims:

- Deterministic policy evaluation based on canonicalized action representations.
- Fail-closed default behavior and explicit `ALLOW`, `ASK`, `DENY`, and `HOLD` outcomes.
- Scoped executors for filesystem, SQLite, and HTTP with built-in constraints.
- Human approval persistence and restart-safe handling for local approvals.
- Hash-chained local receipts and signed checkpoints.
- Local operator console and CLI tooling for policy/lifecycle review.

### Limits that must be respected

- It does not replace OS-level security or cloud IAM.
- It mediates only actions routed through Actentra.
- It does not prove that an external system reached the intended state.
- It cannot guarantee correctness or safety when the host itself is compromised.
- It does not yet implement a durable cross-process identity and provenance model.

## Smallest honest statement of what has been achieved

Actentra has built a convincing local-first action gate and evidence logger for AI tool use. It is strongest as a boundary layer for controlled execution, not yet as a fully autonomous or externally verifiable world-state infrastructure.

## Environment note

A direct `python -m pytest -q` run in this workspace currently fails during collection because the dev dependency `hypothesis` is missing from the environment. The assessment above is therefore grounded primarily in repository source, docs, and existing test files rather than a fully executed local suite.
