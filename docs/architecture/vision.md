# Actentra Project Vision

## Purpose

Actentra should become a compact, durable execution and evidence layer for agentic systems, not a general-purpose AI application or a replacement for broader systems security.

Its mission is simple:

> An agent proposes an action; Actentra evaluates and constrains that action; the execution path records what happened and with what evidence.

## Core principles

1. Deterministic enforcement outside the model.
2. Fail-closed policy evaluation.
3. Clear trust and provenance boundaries.
4. Evidence that distinguishes observed, reported, and verified facts.
5. Local-first usability without pretending to be a remote control plane.
6. Small, auditable components with explicit limits.
7. A minimal but credible path from action to outcome to evidence.

## What Actentra should become

Actentra should be the small boundary that turns a probabilistic agent proposal into a constrained and auditable execution record. It should be useful across frameworks and tool ecosystems, but it should remain a narrow boundary technology rather than a large orchestration platform.

## What it should not become

- a general chatbot,
- a broad world model,
- a cloud control plane,
- a generic distributed orchestrator,
- a replacement for OS or cloud IAM,
- or a model-judging authority in the critical path.

## Scope and boundaries

The credible initial scope is:

- Python SDK and CLI integration,
- local policy enforcement,
- scoped executors,
- human approval for consequential operations,
- durable receipts and checks,
- a small operator interface,
- and a minimal evidence layer for observed postconditions.

The project should not move to remote multi-tenant or distributed control-plane claims until the identity and evidence model is strong enough to support them.

## Strategic direction

The long-term value of Actentra is not a bigger feature list. It is a disciplined trust layer that can reliably answer:

- who proposed the action,
- what context was trusted,
- what policy decided,
- whether a human approved it,
- what exact executor ran it,
- and what evidence supports the outcome.

That question matters more than any single model or workflow abstraction.
