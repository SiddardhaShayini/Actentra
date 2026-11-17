# Actentra Improvements and Enhancements

## 1. Make trust boundaries explicit

### Problem

The project uses request-supplied session, agent, and provenance values in several paths. This is fine for a single-user local app, but not enough for any safety claim involving untrusted or remote callers.

### What exists now

- SDK and gateway accept metadata such as `session_id`, `agent_id`, and provenance.
- Policy evaluation is deterministic and local.

### Missing

- A clear model of trusted identity and delegated authority.
- A distinction between local metadata and authenticated operator identity.

### Expected benefit

The execution boundary becomes easier to reason about and safer to deploy beyond the local loopback environment.

### Complexity

Medium.

## 2. Add a state-verification layer

### Problem

The system records action results, but not whether the intended real-world effect was actually observed.

### What exists now

Decision/outcome receipts and canary tooling exist.

### Missing

- postcondition verification,
- freshness metadata,
- provenance of an observation,
- uncertainty reporting.

### Expected benefit

The project shifts from “execution happened” to “the intended state was observed and remains fresh.”

### Complexity

Medium to Large.

## 3. Enforce lifecycle semantics consistently across all entry points

### Problem

The same lifecycle language appears across the SDK, gateway, CLI, and MCP layers, but identity, provenance, and outcome semantics differ by path.

### What exists now

- Local workflow exists in multiple surfaces.
- A normative lifecycle contract is documented.

### Missing

- one truly canonical lifecycle implementation,
- uniform validation across boundary types,
- explicit semantics for `approved`, `dispatched`, `completed`, and `unknown`.

### Expected benefit

Fewer edge-case regressions and a simpler operator experience.

### Complexity

Medium.

## 4. Tighten evidence quality labels

### Problem

There is a strong difference between direct local execution evidence and independent external verification.

### What exists now

Receipt records include action hashes and result metadata, but not a clear evidence taxonomy.

### Missing

- `locally_observed`, `caller_reported`, `externally_verified`, `stale`, `unknown` categories.

### Expected benefit

Auditors and developers can better tell whether a result is a fact, a report, or an assumption.

### Complexity

Small to Medium.

## 5. Make restart semantics explicit and testable

### Problem

Some long-lived state is process-local and is lost on restart even though approvals and receipts persist.

### What exists now

- persistent approvals exist,
- some recovery helpers exist,
- pending outcomes can be recovered.

### Missing

- a rigorous restart contract,
- actual persistence semantics for taint, budgets, rate limits, and warrants,
- and clear policy for ambiguous in-flight crossings.

### Expected benefit

Operators can reason accurately about what survives a reboot and what does not.

### Complexity

Medium.

## 6. Improve canary and replay fidelity

### Problem

The project already has policy canary and replay capabilities, but not yet full fidelity to historical provenance, timing, and taint semantics.

### What exists now

- replay and canary code exists,
- corpus and risk-based checks are present.

### Missing

- historical provenance replay,
- time-dependent or taint-sensitive replay fidelity,
- a clear distinction between “historical comparison” and “production prediction.”

### Expected benefit

The project can trust canary results as advisory signals, and later as release gates.

### Complexity

Medium.

## 7. Keep the architecture small and disciplined

### Problem

The project is already large enough to drift into overbuilding.

### What exists now

The architecture is modular and mostly coherent.

### Missing

- strong guardrails against feature sprawl,
- explicit “not in scope” decisions,
- practical prioritization around the local-first boundary.

### Expected benefit

A mature platform with a minimal trust surface rather than an unbounded agent operating system.

### Complexity

Small.

## 8. Best immediate next step

A narrow observation-verification layer for a single resource class is the most valuable next improvement. It would not require a broad rewrite, but it would answer the central unsolved question: how does Actentra distinguish an intended action from an actually verified postcondition?
