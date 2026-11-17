# Actentra Architectural Review

## Overview

Actentra’s architecture is coherent and modular. It is built around a deterministic core, a small number of integration surfaces, and a durable local audit trail. The project is strongest where it keeps policy evaluation separate from model behavior and keeps enforcement outside the agent’s reasoning loop.

The main architecture is:

1. Adapter or caller layer: Python SDK, LangChain/OpenAI adapters, MCP proxy, HTTP gateway.
2. Canonicalization and envelope layer: normalize tool calls and compute a stable action hash.
3. Policy and risk layer: evaluate rules, taint, budgets, and session context.
4. Approval and dispatch layer: persist approvals when necessary and dispatch only through configured executors.
5. Evidence layer: write decision and outcome receipts into SQLite and expose verification/reporting tools.

## Core strengths

### 1. Deterministic policy boundary

The architecture intentionally keeps the enforcement path independent from the model. This is the project’s most important design choice. The risk engine and policy engine are rule-based rather than LLM-driven, which gives Actentra a strong basis for auditable decisions.

Relevant files:

- [`core/actentra_core/policy.py`](core/actentra_core/policy.py)
- [`core/actentra_core/risk.py`](core/actentra_core/risk.py)
- [`core/actentra_core/budgets.py`](core/actentra_core/budgets.py)

### 2. Clean action identity model

The project treats an action as a canonical object with a stable hash. This is the right abstraction for safety-critical AI execution. It prevents a “different action under the same description” problem and gives a consistent record key for policy decisions and approvals.

Relevant files:

- [`core/actentra_core/envelope.py`](core/actentra_core/envelope.py)
- [`core/actentra_core/canonicalize.py`](core/actentra_core/canonicalize.py)
- [`spec/canonical_test_vectors.json`](spec/canonical_test_vectors.json)

### 3. Local-first evidence capture

The database-backed receipt flow is one of the project’s most mature capabilities. It gives a durable record of decision, result, and outcome classifications, and it supports review, export, replay, and report generation.

Relevant files:

- [`core/actentra_core/receipts.py`](core/actentra_core/receipts.py)
- [`core/actentra_core/reporting.py`](core/actentra_core/reporting.py)
- [`core/actentra_core/checkpoints.py`](core/actentra_core/checkpoints.py)

### 4. Real executor constraints

The filesystem, SQLite, and HTTP executors are not just placeholders. They impose specific constraints, including path containment, row caps, method filtering, SSRF defenses, and other explicit rules. This shows the project has reached beyond conceptual design into operational guardrails.

Relevant files:

- [`executors/actentra_executors/fs.py`](executors/actentra_executors/fs.py)
- [`executors/actentra_executors/sqlite.py`](executors/actentra_executors/sqlite.py)
- [`executors/actentra_executors/http.py`](executors/actentra_executors/http.py)

## Key architectural weaknesses

### 1. Identity and trust semantics are not yet strong enough

The gateway and service layer presently accept request-derived session and provenance values. That is acceptable for a loopback local demo, but it is not a trust boundary for untrusted or remote callers. The architecture needs a clear distinction between:

- caller-supplied metadata,
- authenticated operator identity,
- verified origin of evidence,
- and trusted execution context.

Without this, an actor can claim the identity and provenance that they want the system to honor.

### 2. World-state is not a first-class abstraction

The system records an action and an outcome, but not a durable representation of the actual world state that the action intended to change. That is the single biggest missing architectural layer between “we ran something” and “the intended effect really occurred.”

### 3. Process-local controls are not durable by default

Taint, budgets, rate limits, and some warrant state are process-local. This works for a local prototype but not for a restart-resilient system that can claim cross-session continuity.

### 4. Evidence is good for audit, but not necessarily for proof

The chain is valid locally, and the record is tamper-evident in its own database. But a valid receipt does not mean the external world state is correct or independently verified. The architecture needs a clear distinction between:

- observed result,
- reported result,
- and independently attested state.

### 5. The design is stronger than the product claims

The documentation is ambitious, but the real project is a local enforcement and audit layer. It is not yet proven to be a secure remote control plane or a general-purpose autonomous execution fabric.

## Architectural judgment

Actentra has a wise core design and a disciplined execution philosophy:

- enforce outside the model,
- canonicalize actions before law-like decisions,
- make policy deterministic,
- incorporate cross‑agent handoff primitives (signed handoff objects with expiry and scope),
- add a narrow observation layer for post‑condition verification, and
- extend evidence records with freshness, provenance, and verification status.
- bind human approvals to exact action hashes,
- log results durably,
- keep the trust domain local and explicit.

Its weakness is not in the foundational idea. The weakness is that the project does not yet fully separate what is “known,” “reported,” and “verified.” That distinction is essential if the platform is ever to support cross-agent coordination or consequential real-world actions.

## Recommendation

The architecture should stay close to its current form: deterministic core, scoped executors, local approvals, durable receipts, and a small operator surface. The next major improvement should not be a large platform rewrite. It should be a small, explicit evidence layer that records freshness, observation method, and trust source for post-action state.
