# Actentra Research Gaps and Prior Art

## Summary

Actentra’s core architecture is well aligned with a real research need: controlled execution for LLM-driven or agentic tool use. The gap is not “does the concept exist?” It is “which parts are still too weak to support safe consequential action and continuity across agents, systems, and time?”

## A. Verifiable state

### Problem

Actentra records decisions and outcomes, but it does not yet have a first-class representation of the actual external world state that actions are supposed to affect.

### Why it matters

Without verifiable state, the system knows what it decided but not whether the real postcondition holds.

### Current state

The project has receipts, envelopes, and canary/replay tooling, but not a durable state-observation model with freshness, provenance, and uncertainty.

### Research direction

Add a narrow observation layer for one resource type, such as file existence or a content hash, with a clear claim format:

- observed state,
- observer identity or trust domain,
- observation method,
- timestamp,
- freshness,
- and uncertainty flag.

This is more credible than storing broad snapshots or reusing local logs as proof of real-world truth.

## B. Evidence and provenance

### Problem

A result hash is not the same as a verified fact. The system needs to distinguish local execution success from independently observed or externally attested facts.

### Current state

The receipts code and reporting tools store useful metadata, but there is no general evidence model for provenance, verification method, and trust domain.

### Research direction

Treat evidence as typed records with fields such as:

- source,
- observer,
- collection method,
- trust level,
- freshness,
- verification status,
- and relation to a decision or action.

## C. Causal execution history

### Problem

The project understands action-by-action decisions well, but it does not yet expose a durable causal trace that proves how a state transition or observed effect relates to one or more agent actions.

### Current state

There are decision records, outcome records, and canary replay, but not a compact, typed graph of causal lineage in the core design.

### Research direction

Use SQLite relationships or a highly constrained schema to represent:

- action -> decision -> result,
- evidence -> observation -> state assertion,
- and cross-reference -> subsequent action.

This is a bounded, local-first graph rather than a general-purpose distributed knowledge graph.

## D. Cross-agent continuity

### Problem

Safe continuation across agents is difficult because different agents may disagree on authentication, task ownership, and evidence quality.

### Current state

The project has a local operator model and approval records, but not a formal cross-agent handoff or continuity contract.

### Research direction

Prototype a narrow, signed handoff object with:

- handing agent,
- receiving agent,
- task ID,
- allowed scope,
- expiry,
- proof of prior decision,
- and required observation before continuation.

Do not generalize this before the underlying identity and evidence model is trustworthy.

## E. Uncertainty management

### Problem

Safety systems must distinguish between known, reported, unverified, stale, ambiguous, and failed states.

### Current state

There is a broad audit surface, but not a universal uncertainty model in the execution core.

### Research direction

Add first-class lifecycle states such as:

- verified,
- reported,
- failed,
- stale,
- unknown,
- and rejected.

These states must be defined across both execution outcomes and external observations.

## F. Recovery and consistency

### Problem

Crash recovery, duplicate operations, and ambiguous partial execution remain difficult when actions can be external or semi-autonomous.

### Current state

The project has recovery helpers, pending approvals, and unknown outcome handling. This is a strong start, but recovery semantics must be made explicit and bounded.

### Research direction

Distinguish:

- not yet dispatched,
- dispatched but unconfirmed,
- executed and reported,
- and externally reported without direct verification.

Only then can restart recovery be truly safe and non-misleading.

## G. Distributed agent coordination

### Problem

Multiple agents coordinating consequential operations can produce conflicting or unsafe actions unless they share a common, verifiable authority model.

### Current state

Actentra is local-first and not yet designed for distributed coordination across a multi-agent or multi-host environment.

### Research direction

A credible first step is a shared, append-only event log with explicit ownership and scope, not a general coordination platform. Coordination should be layered above deterministic action control.

## H. Long-term accountability

### Problem

An organization will eventually require a clear answer to: what happened, who authorized it, what evidence supports it, and which permissions were exercised.

### Current state

The project is close to providing the “what happened” and “who approved it” pieces, but still weaker on the “why was this trusted and how was it externally verified?” piece.

### Research direction

The accountability model should include:

- authority,
- scope,
- outcome,
- evidence,
- freshness,
- and human review traces.

## Prior art and related work

The project already fits a broader ecosystem of runtime action control and agent governance research. Relevant areas include:

- runtime authorization and action gating,
- durable execution and event-sourcing patterns,
- database consistency and audit logging,
- cryptographic provenance and signed records,
- safety for autonomous tool use,
- multi-agent orchestration and handoff protocols,
- and software supply-chain integrity practices.

The important distinction is not whether these concepts exist—they do—but whether Actentra is building the right minimal layer for incremental trust and evidence, rather than overbuilding a platform or depending on uncertain model judgment.

## Most promising research directions for this repo

1. Narrow, typed state observations with freshness and provenance.
2. Explicit evidence classes instead of generic “success” outcomes.
3. Strict handoff and continuity tokens for multi-agent work.
4. Causal lineage captured as ordinary SQLite references rather than a large graph system.
5. A tighter classification of “verified,” “reported,” and “unknown.”

These are likely to be more meaningful than a broad new distributed platform.
