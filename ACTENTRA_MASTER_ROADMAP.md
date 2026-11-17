# Actentra Master Roadmap

## Stage 0 — Existing foundation

### Purpose

Preserve the core strengths already present in the repo: deterministic policy, scoped executors, local approval flow, durable receipts, and a usable operator/UI surface.

| Task | Priority | Problem statement | Expected outcome | Dependencies | Relevant components | Acceptance criteria | Testing | Complexity |
|---|---|---|---|---|---|---|---|---|
| Consolidate lifecycle semantics | Critical | Different surfaces follow similar but not identical execution semantics. | One canonical lifecycle for approval, dispatch, completion, and unknown states. | None | SDK, gateway, CLI, receipts, docs | All paths share same lifecycle states and labels. | Unit tests across service and SDK surfaces | Medium |
| Clarify identity and trust boundaries | Critical | Caller-supplied identity metadata is not a trust boundary. | Explicit trusted-vs-untrusted metadata model. | Previous task | gateway services, boundary, docs | Identity model documented and enforced. | Contract tests | Medium |
| Lock down approval API contract | Critical | Missing or malformed approval values may be misinterpreted. | Explicit boolean requirements and rejection of malformed payloads. | Lifecycle semantics | `http_service.py`, tests | Invalid approval payloads rejected with clear errors. | Endpoint regression tests | Small |

## Stage 1 — Critical improvements

### Purpose

Fix the security and reliability gaps that matter most before the project is described as a strong operational boundary.

| Task | Priority | Problem statement | Expected outcome | Dependencies | Relevant components | Acceptance criteria | Testing | Complexity |
|---|---|---|---|---|---|---|---|---|
| Add evidence-quality taxonomy | Critical | The system does not distinguish between local success, external verification, and report-only states. | `verified`, `reported`, `unknown`, `stale`, and `locally_observed` states are first-class. | Identity model | receipts, reporting, docs | A result record always carries its evidence status. | Schema and unit tests | Medium |
| Persist important process-local state | High | Budgets, taint, and control state are lost on restart. | Local control state survives restart where required. | Lifecycle semantics | budgets, receipts, policy runtime | Restart behavior is explicit and test-backed. | Recovery tests | Medium |
| Repair replay and canary fidelity | High | Canary replay does not yet faithfully model historical context. | Replay matches the same trust and temporal assumptions as live execution. | Evidence taxonomy | `canary.py`, tests, corpus | For a fixed data set, replay preserves the same verdict categories and assumptions. | Replay and canary tests | Medium |
| Harden external outcome reporting | High | Caller-reported outcomes may not reflect real-world execution. | Outcome records are labeled and validated as external reports unless trustworthy evidence exists. | Evidence taxonomy | `receipts.py`, gateway services | Untrusted external updates cannot masquerade as verified execution. | Unit/integration tests | Medium |

## Stage 2 — Foundational capabilities

### Purpose

Build the minimum capabilities that meaningfully support real postcondition checking and causal continuity.

| Task | Priority | Problem statement | Expected outcome | Dependencies | Relevant components | Acceptance criteria | Testing | Complexity |
|---|---|---|---|---|---|---|---|---|
| State observation model | Critical | No durable, trusted representation of intended state exists. | One narrow observation record for a single resource class, with freshness and provenance. | Evidence taxonomy | receipts, SDK, filesystem executor | Observation records can be verified and linked to an action. | Unit tests and verification checks | Medium |
| Causal trace references | High | No clear way to connect decisions to observed effects and subsequent actions. | Typed references in SQLite for action/evidence lineage. | State observation | receipts, docs | Recorded traces show a cause-effect chain with explicit uncertainty. | Trace validation tests | Medium |
| Narrow signed handoff primitives | High | Multi-agent continuity is not yet represented safely. | A simple signed handoff object with expiry and scope constraints. | State observation + identity model | warrants, receipts | Handoff is rejected if scope or proof is missing. | Contract tests | Medium |

## Stage 3 — Advanced capabilities

### Purpose

Only after the evidence and identity model is trustworthy should the project move into broader coordination or cross-agent innovation.

| Task | Priority | Problem statement | Expected outcome | Dependencies | Relevant components | Acceptance criteria | Testing | Complexity |
|---|---|---|---|---|---|---|---|---|
| Cross-agent continuity prototype | Medium | A safe continuation model for multiple agents is still missing. | One constrained prototype with explicit handoff and evidence references. | Signed handoff primitive | gateway, SDK, receipts | Prototype tested under a small handoff scenario. | End-to-end scenario tests | Large |
| Coordination model for multiple agents | Medium | The conflict and conflict-resolution model is still unspecified. | A limited coordination contract for safe concurrent delegation. | Handoff + evidence model | policy, receipts, docs | Formalized lock/ownership rules | Model tests | Large |
| Advanced verification and review UX | Medium | Operator inspection can become difficult as evidence grows. | Review views show evidence quality, freshness, and trust boundaries clearly. | State observation | `console.html`, services | Human review can distinguish verified vs reported outcomes. | UI and integration tests | Medium |

## Stage 4 — Long-term vision

### Purpose

Keep Actentra as a small, durable, generalized execution and evidence layer for agentic systems without drifting into a general AI platform.

| Task | Priority | Problem statement | Expected outcome | Dependencies | Relevant components | Acceptance criteria | Testing | Complexity |
|---|---|---|---|---|---|---|---|---|
| Small, local-first trust substrate | High | The project should remain infrastructure, not a general-purpose chatbot or broad agent OS. | A trusted local boundary that can be integrated with many agent frameworks. | All previous stages | core, SDK, CLI, gateway | Clear boundaries and a compact trust surface | Integration tests | Medium |
| Interoperable evidence format | Medium | Different tools need a common way to express observations and receipts. | A machine-friendly evidence contract. | observation model | spec, SDK, docs | Schema is used across entry points | Schema tests | Medium |
| Optional distributed anchoring | Low | Local database integrity is useful, but external anchoring is better when needed. | Signed checkpoints and optional external anchoring for stronger audit claims. | evidence + receipts | checkpoints, docs | Anchoring is optional, explicit, and documented | Integration tests | Medium |

## Recommended next milestone

The smallest meaningful next step is not a large platform project. It is a narrow postcondition-observation layer for one resource class, backed by clear evidence labels and explicit reaction to stale or unknown state.
