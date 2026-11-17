# Actentra Plan V5

## Status and direction

Actentra has moved from a skeletal Phase 0 concept into a credible local-first execution boundary with broad source coverage. The project’s strongest real asset is not novelty; it is the disciplined combination of deterministic policy, scoped executors, approval persistence, logs, and local auditability.

The next phase is not a major rewrite. The next phase is to turn the project from “a strong local safety boundary” into “a trustworthy evidence-backed execution model.”

## V5 priorities

1. Clarify trust boundaries and identity semantics.
2. Define evidence quality explicitly: observed, reported, verified, stale, and unknown.
3. Add a small state-observation mechanism for one resource class.
4. Make replay/canary fidelity stronger and more operationally honest.
5. Tighten restart semantics and recovery behavior for stateful controls.
6. Keep the architecture small and local-first.

## Key workstreams

### 1. Trust and lifecycle hardening

- Make the lifecycle contract consistent across SDK, gateway, CLI, and MCP entry points.
- Require explicit approval semantics and reject malformed or ambiguous payloads.
- Separate request metadata from authenticated identity and validated trust context.

### 2. Evidence and provenance model

- Introduce typed evidence records with provenance and freshness metadata.
- Distinguish local observations from externally attested facts.
- Capture uncertainty explicitly rather than collapsing it into generic success.

### 3. Minimal postcondition verification

- Add a single narrow observation model for workspace file state or similar metadata.
- Link observations to an originating action and persistent evidence record.
- Keep the observation layer read-only and bounded.

### 4. Replay and canary reliability

- Improve replay fidelity for provenance, taint, timing, and budget semantics.
- Use canary as an advisory tool until its historical assumptions are proven.
- Keep the policy canary honest about what it can and cannot prove.

### 5. Restart and recovery clarity

- Determine which runtime state must persist and which can remain process-local.
- Define clear recovery behavior for in-flight or ambiguous crossings.
- Document what is safe to reconstruct and what must remain unknown.

## Dependencies and sequencing

The recommended order is:

1. lifecycle and identity semantics,
2. evidence model,
3. observation model,
4. replay fidelity,
5. restart/recovery,
6. broader coordination work.

## Success criteria for V5

- The project can explain exactly which state is trusted and which is caller-supplied.
- Every result carries an evidence label and uncertainty status.
- A bounded observation layer exists for at least one real resource type.
- Replay and canary can be described as advisory without overstating their power.
- Recovery semantics are documented and testable.

## Practical guidance

Keep the implementation narrow, local, and testable. Do not implement a broad AI control plane, a distributed graph platform, or a generalized multi-agent orchestration system before these foundations are solid.

This is the smallest meaningful next step toward making Actentra a durable execution and evidence substrate for future generations of agentic systems.
