# Actentra — Project Memory 2

**Updated:** 2026-11-16  
**Purpose:** Current handoff for future agents. This file carries forward the durable rules and architecture from `PROJECT_MEMORY.md`, updates the status to reflect the current repository, and adds the V4 evidence/research direction. The original memory remains historical context; routine future memory updates belong in this file, not `PROJECT_MEMORY.md`, unless the user explicitly asks otherwise.

## Project summary

Actentra is a lightweight, local-first, deterministic execution boundary for AI agents. It evaluates tool actions against policy, can require human approval, dispatches through scoped executors, and records decision/execution outcomes. Enforcement must not depend on an LLM.

The current repository is substantially beyond an initial planned MVP: it includes a Python core and SDK, CLI, function-calling and LangChain adapters, MCP stdio proxy, local HTTP gateway/operator console, scoped filesystem/SQLite/HTTP executors, SQLite WAL receipts and pending approvals, policy dry-run/canary/replay, signed checkpoints, secrets and warrant primitives, schemas, corpora, and tests. The project is still an early local-first product/prototype; broad module presence is not by itself proof of a production guarantee.

**Core identity:** Actentra determines whether a mediated action is permitted, how it is constrained/executed, and what its execution path reports. Verifying whether resulting external state exists and remains valid is a possible additive capability, not a current guarantee. Use [PLAN_V4.md](PLAN_V4.md) as the current strategic direction and [docs/product-status.md](docs/product-status.md) as the implementation capability matrix, subject to source/test evidence.

## Required context for agents

1. Before project changes, read [PLAN_V4.md](PLAN_V4.md) and this file. Consult [docs/product-status.md](docs/product-status.md), [docs/lifecycle-contract.md](docs/lifecycle-contract.md), [docs/guarantees-and-limits.md](docs/guarantees-and-limits.md), and relevant source/tests for the affected behavior.
2. `PROJECT_MEMORY.md` is retained as history. **Update `PROJECT_MEMORY_2.md`, not `PROJECT_MEMORY.md`, for routine memory maintenance.** Preserve prior entries in this file and append a dated/timed entry; do not silently rewrite history.
3. Keep changes surgical, preserve existing work, follow the current lifecycle contract, and validate the exact behavior with the smallest relevant test/check when implementation is requested.
4. Do not treat plans, README claims, or historical reviews as proof of current behavior. Inspect current source and tests. Label static observations, test evidence, assumptions, and proposals distinctly.
5. Do not claim that a receipt hash proves external truth, that approval means execution, or that a successful caller report independently verifies an outcome.
6. Avoid adding infrastructure or dependencies without a concrete use case. Prefer existing `AppServices`, `ExecutorRegistry`, `ReceiptStore`, SQLite, CLI, and embedded console.

## Architecture reference

- **Core:** `core/actentra_core/` — envelope and canonicalization, risk, YAML policy/verdicts, rate/cumulative budgets, receipts and pending approvals, canary, checkpoints, reporting, and warrants.
- **SDK/adapters:** `sdk/python/actentra/` — `Boundary.execute()` / `@guard`, secrets broker, function-calling adapter, and LangChain wrapper.
- **Executors:** `executors/actentra_executors/` — scoped filesystem, SQLite, and SSRF-defended HTTP.
- **Gateway:** `gateway/actentra_gateway/` — `AppServices`, executor registry, HTTP service, embedded console, MCP stdio proxy.
- **CLI:** `cli/actentra_cli/main.py` — policy, simulation/replay, gateway, MCP, audit, archive, report, checkpoint, warrant, and approval operations.
- **Contracts and examples:** `spec/`, `policies/`, and `corpus/`.
- **Tests/CI:** `tests/` includes unit, golden, chaos, property, replay, and performance suites; [ci.yml](.github/workflows/ci.yml) runs Windows Python 3.12 CI checks.
- **Python/runtime dependencies:** Python `>=3.12`; PyYAML, `cryptography`, and Typer are runtime dependencies. The product uses standard-library SQLite and HTTP components.

## Historical context carried forward

The original memory contains the detailed dated implementation log. Retain it as historical context; do not copy old status claims forward as current facts. Key milestones and lessons recorded there:

- **2026-11-12:** Established the spec-first kernel, SDK/CLI, filesystem executor, MCP proxy, SQLite executor, schemas, starter policy, incident corpus, and initial tests. Canonicalization must reject suspicious leading/trailing whitespace instead of silently normalizing it. Python SQLite connection context managers do not close their handles; use explicit close/cleanup where needed.
- **2026-11-13:** Added HTTP/SQLite executors, approvals, gateway/services/console, budgets, taint, canary, warrants, secrets, checkpoints, reports, and lifecycle documentation. Windows symlink/junction checks may require privileges; keep deterministic mocked coverage in addition to privilege-gated tests. Use a controllable clock for TTL tests instead of timing-sensitive sleeps.
- **2026-11-13 to 2026-11-15:** Addressed historical review findings around approval validation/claims, redirects, remote binding gates, UI escaping, session taint/budget hooks, outcome uniqueness, envelope checks, and bounded receipt operations. Later source and tests supersede the corresponding old review snapshot where confirmed.
- **2026-11-14 to 2026-11-15:** Expanded end-to-end warrant/secret integration, streaming receipt export/verification/archive, canonicalization vectors, and performance tests; aligned product status and documentation with features believed implemented at that time.

The original log reports test/lint/type-check results at historical points. They were not rerun as part of this memory/plan analysis and must not be presented as current validation.

### Main action lifecycle

Agent/caller proposal → canonical `ActionEnvelope` → deterministic risk and policy evaluation → `DENY`/`HOLD`/`ASK`/`ALLOW` → persisted decision → explicit approval if required → scoped executor or registered callable → outcome record → optional separate state observation.

Relevant entry points:

- `Boundary.execute()` / `Boundary.dry_run()` in [boundary.py](sdk/python/actentra/boundary.py).
- `AppServices.submit_crossing()`, `_dispatch_and_record()`, `resolve_approval()`, and `execute_approved_crossing()` in [services.py](gateway/actentra_gateway/services.py).
- HTTP routes in [http_service.py](gateway/actentra_gateway/http_service.py), including `/v1/crossings`, `/v1/crossings/pending`, approval/execute/outcome continuations, `/v1/receipts`, `/v1/verify`, `/v1/bundle/export`, and `/ui`.
- Persistent records, pending approvals, envelope context, receipt verification, and recovery helpers in [receipts.py](core/actentra_core/receipts.py).

## Existing guarantees and their limits

- **Deterministic enforcement:** The core policy path does not need LLM inference. Default policy verdicts are fail-closed.
- **Approval:** SQLite stores pending approval status/expiry; approvals are action-hash scoped and the gateway has an atomic claim-for-execution path. Approval is not execution.
- **Audit:** Decision/outcome receipt records are linked by a SHA-256 hash chain; envelopes and approvals are persisted in SQLite. This detects many accidental/local edits but is not immutable against an administrator who can rewrite the database unless an independently protected checkpoint anchors it.
- **Outcome:** An Actentra-registered executor reports its own result to the service; external execution can be reported by a caller and is labeled `caller-reported`. Neither a caller-supplied result hash nor a result hash alone proves current real-world state.
- **Context binding:** The action hash covers envelope version, session ID, agent ID, and action. It does not currently bind all provenance/intent context. Envelope integrity verification therefore should not be described as integrity over every trust-relevant field.
- **Restart:** SQLite receipts, action envelopes, and approval statuses persist. Taint, budget counters, policy rate-limit buckets, freeze state, and warrant-use counters are process-local. `recover_pending_outcomes()` and `recover_pending_approvals()` exist, but are not automatically invoked by a production startup call site in the inspected source.
- **Recovery caution:** Do not blindly recover every allowed decision without an outcome as `unknown`: some decision-only crossings are awaiting external execution/outcome. First distinguish not-dispatched from dispatch-started/uncertain.
- **Identity:** Gateway `session_id`, `agent_id`, and provenance may arrive in caller input. Treat them as caller claims unless a trusted integration assigns/authenticates them.
- **Security boundary:** Actentra mediates only calls routed through it. It does not replace OS/cloud IAM or protect against a fully compromised host. Keep loopback as the normal mode; explicit remote binding does not make the built-in plain-HTTP server a remote control plane.
- **Audit/resource bounds:** Receipt pages and request bodies have caps; streaming audit features exist. Some full-history paths (e.g. audit bundle/canary materialization) can still consume memory proportional to log size.

## Product and change conventions

- Preserve the small local-first design: Windows 11, 8 GB RAM, Intel i5, CPU-only, no requirement for Docker or a local GPU.
- Keep decision-making deterministic and explainable. A model may propose an action but must never authorize itself.
- Preserve `DENY`/`HOLD`/`ASK`/`ALLOW` distinctions and fail closed on invalid input or unavailable durable decision recording.
- Use existing schemas and patterns; version persisted data changes and test old-database compatibility.
- Keep identity and provenance authority explicit; do not trust model-supplied `agent_id`, intent, or trust labels as authentication.
- Prefer explicit typed lifecycle and evidence state over implicit booleans. Distinguish proposal, decision, approval, dispatch, outcome, observation, and stale/unknown state.
- Add evidence as a small, separate, versioned data shape. Minimize retained data; do not store raw file/API contents by default.
- Keep state observations scoped, timestamped, source-labeled, and freshness-bounded. A verified observation is only as trustworthy as its verifier and trust domain.
- Build causal trace with typed SQLite references and views; do not add a graph database just to render a graph.
- Keep `PROJECT_MEMORY_2.md` current when project files are created/edited/moved/deleted: append local date/time, paths changed, reason, key decisions/assumptions, and validation status. Do not record secrets or unnecessary personal data.

## Hardware and lightweight-work rules

Development is on a **Windows 11 laptop with 8 GB RAM, Intel i5 CPU, and no GPU**. Lightweight operation is a core requirement:

- Avoid actions likely to cause out-of-memory conditions, sustained high memory use, CPU saturation, or disruptive lag.
- Prefer small incremental work and bounded processes, workers, queues, test data, and timeouts. Avoid unnecessary parallel builds or test runs.
- Do not start heavy VMs, Docker, large model downloads, GPU/ML stacks, load tests, fuzzing, or other resource-intensive jobs on the laptop by default. Keep heavy or long-running checks opt-in or in CI where practical.
- Do not enable a background daemon or automatic startup by default. Ask before an action whose resource impact is uncertain or potentially disruptive.
- Treat resource figures in plans/tests as targets to measure on the actual device, not guarantees.
- Prefer SQLite and existing standard-library components over network services, vector stores, or multiple processes.
- Hosted inference is optional. Before sending project data to any provider, explain the data/privacy implications and use only user-authorized credentials. Free-tier availability and pricing may change.

## GPU / High-Resource Testing Guidance

If a task requires GPU resources, larger models, or hardware beyond the available local machine:

- Inform the user before proceeding with that approach.
- Explain why local execution is unsuitable.
- Recommend an appropriate alternative, such as Kaggle notebooks with GPU.
- Provide clear, step-by-step guidance for setting up and running the experiment on Kaggle.
- Keep local development and GPU experimentation clearly separated.
- Never assume GPU access or silently introduce resource-intensive requirements.

This guidance does not imply that Actentra’s authorization or first demonstration needs GPU resources; they do not.

## Status and strategy

- Near-term priority: reconcile lifecycle/identity/evidence claims and deliver a restart-safe local gateway demonstration using existing components.
- Next high-value research step: one narrowly scoped read-only state verifier with explicit freshness and provenance.
- Later: causal references in SQLite, then a constrained A→B→C handoff experiment.
- Defer general world models, autonomous agent teams, graph/vector databases, cloud control plane, SSO, desktop shell, and broad connector expansion until real user need and measured constraints justify them.
- Use [PLAN_V4.md](PLAN_V4.md) as the project roadmap; keep [docs/product-status.md](docs/product-status.md) aligned with implementation evidence.

## Change log

### 2026-11-16 10:31 IST

- Created `PLAN_V4.md` and `PROJECT_MEMORY_2.md`; did not modify `PROJECT_MEMORY.md` or source/configuration files.
- Why: provide a source-grounded current roadmap and a current handoff file that future agents update instead of the original memory file.
- Analysis: static inspection only. No commands, tests, builds, services, installs, or runtime experiments were executed.
- Key decisions: preserve Actentra’s deterministic action-boundary purpose; prioritize an existing-component local demo; evaluate state evidence as an additive, scoped SQLite capability; defer general graph infrastructure and multi-agent continuity until identity/evidence foundations are established.

### 2026-11-16 15:15 IST

- Implemented Phase 0 (Contract and evidence baseline reconciliation) and Phase 1 (Restart-safe action demonstration and execution lifecycle fixes).
- Files modified/created:
  * `gateway/actentra_gateway/demo.py`: Added full end-to-end restart-safe demonstration runner (`run_gateway_demonstration`).
  * `gateway/actentra_gateway/__init__.py`: Exported demo functions and types.
  * `examples/gateway_demo.py`: Added standalone demonstration entry point script.
  * `cli/actentra_cli/main.py`: Added `actentra demo-gateway` command and `--gateway` flag to `actentra demo`.
  * `sdk/python/actentra/boundary.py`: Added `Boundary.consume_approval` for explicit in-memory grant consumption.
  * `gateway/actentra_gateway/services.py`: Fixed `execute_approved_crossing` to honor SQLite-persisted approvals across process restarts and atomically claim them with `claim_approval_for_execution`; automated expired approval cleanup on startup.
  * `docs/lifecycle-contract.md`: Reconciled lifecycle states (`CONSUMED`), persistence scope vs. process-local state, identity authority, outcome evidence tiers (first-party vs caller-reported), and restart recovery semantics.
  * `docs/product-status.md`: Updated capability matrix and test mapping to document restart-safe gateway demonstration and evidence tiers.
  * `README.md`: Added demonstration instructions to Quick Start.
  * `tests/unit/test_gateway_demo.py`: Added comprehensive unit tests for demo execution, CLI invocation, and HTTP handler dispatch.
  * `tests/unit/test_app_services.py`: Added unit test verifying execution of approved crossing across process restarts.
- Key decisions & rationale:
  * Preserved deterministic policy evaluation and deny-by-default architecture; zero model in enforcement loop.
  * Preserved backwards compatibility of Envelope v1 canonical hashes and test vectors while clarifying context binding limits.
  * Maintained strict separation between first-party executor results and caller-reported external outcomes.
  * Avoided adding any new server processes, heavy frameworks, or external dependencies.
- Validation:
  * All 123 tests passing with 0 failures (`uv run pytest -m "not slow"`).
  * `uv run ruff check` clean (all source files pass).
  * `uv run mypy` strict type check passes with 0 issues across all source files.
  * `actentra demo-gateway` executed and verified manually.

### 2026-11-16 15:55 IST

- Implemented Phase 2 (Minimal Verifiable State for One Resource Type) according to PLAN_V4.md.
- Files modified/created:
  * `spec/observation.v1.schema.json`: Formal JSON Schema for version 1 observation records with strict type constraints.
  * `core/actentra_core/observations.py`: Implemented `ObservationRecord`, canonical `compute_observation_hash`, `build_observation`, and ISO-8601 `is_fresh` expiry checking.
  * `core/actentra_core/receipts.py`: Added `observations` SQLite table with indexes on `(subject_resource, observed_at)` and `crossing_id`, along with `record_observation`, `get_observation`, `get_latest_observation`, `list_observations`, and `count_observations`.
  * `core/actentra_core/__init__.py`: Exported `ObservationRecord`, `build_observation`, and `compute_observation_hash`.
  * `executors/actentra_executors/verifiers.py`: Created `WorkspaceFileVerifier` read-only verifier capturing SHA-256 digests and claims (`exists`, `absent`, `digest_match`) strictly confined within workspace root (preventing path traversal).
  * `executors/actentra_executors/__init__.py`: Exported `WorkspaceFileVerifier`.
  * `gateway/actentra_gateway/services.py`: Added observation methods (`verify_state`, `get_observation`, `list_observations`) to `AppServices` with default workspace file verifier.
  * `gateway/actentra_gateway/http_service.py`: Added REST endpoints (`POST /v1/observations/verify`, `GET /v1/observations`, `GET /v1/observations/{id}`) and included observations in `POST /v1/bundle/export`.
  * `cli/actentra_cli/main.py`: Added `observation` CLI subcommand group (`actentra observation verify`, `list`, `show`).
  * `tests/unit/test_observations.py`: Added 7 comprehensive unit tests covering record validation, hash integrity, freshness, workspace containment, service integration, HTTP dispatch, and CLI commands.
  * `docs/product-status.md`: Updated capability matrix and invariant-to-test mapping to reflect Verifiable World State Observation as Supported.
- Key decisions & rationale:
  * Additive schema: observations exist in a separate SQLite table alongside receipts, without mutating receipt envelopes or breaking backwards compatibility.
  * Separate evidence tier: observations are explicitly marked with `verifier_id` and `trust_domain` (e.g. `local_host`) and have finite validity via `expires_at`, maintaining clear separation from caller-reported outcomes.
  * Strict confinement: `WorkspaceFileVerifier` rejects any attempt to observe paths outside workspace boundaries or path traversal attacks.
- Validation:
  * All 130 tests passing with 0 failures (`uv run pytest -m "not slow"`).
  * `uv run ruff check core executors gateway sdk cli tests examples` passes with 0 issues.
  * `uv run mypy core executors gateway sdk cli tests/unit/test_observations.py` passes with 0 issues.

### 2026-11-16 16:15 IST

- Implemented Phase 3 (Causal trace as SQLite references and DAG integrity) according to PLAN_V4.md.
- Files modified/created:
  * `spec/causal-trace.v1.schema.json`: Formal JSON Schema for version 1 causal trace graphs and timelines.
  * `spec/causal-link.v1.schema.json`: Formal JSON Schema for version 1 explicit causal link records.
  * `core/actentra_core/causal.py`: Core causal module with `CausalLink`, `CausalTraceNode`, `CausalTraceEdge`, `CausalTimelineEvent`, `CausalTrace`, `detect_cycles` (DFS-based cycle detection), and `build_causal_trace` graph/timeline reconstructor.
  * `core/actentra_core/receipts.py`: Added `causal_links` table with indexes on `(source_type, source_id)` and `(target_type, target_id)`; added `record_causal_link` (with cycle prevention), `get_causal_link`, `list_causal_links`, `delete_causal_link`, `count_causal_links`, and `get_outcome_receipt`.
  * `core/actentra_core/__init__.py`: Exported causal models and helpers (`CausalLink`, `CausalTrace`, `build_causal_trace`, etc.).
  * `gateway/actentra_gateway/services.py`: Added trace methods (`get_causal_trace`, `record_causal_link`, `list_causal_links`, `delete_causal_link`) to `AppServices`; included `causal_links` in `export_audit_bundle`.
  * `gateway/actentra_gateway/http_service.py`: Added REST endpoints (`GET /v1/trace/{id}`, `GET /v1/trace/links`, `POST /v1/trace/links`, `DELETE /v1/trace/links/{id}`).
  * `cli/actentra_cli/main.py`: Added `trace` CLI subcommand group (`actentra trace show`, `link`, `list`, `delete`) with ASCII DAG/timeline rendering and `--json` support.
  * `tests/unit/test_causal_trace.py`: Added 7 comprehensive unit tests (schema validation, DAG cycle detection, intrinsic lifecycle reconstruction, approval/task linkage, HTTP endpoints, and CLI commands).
  * `docs/product-status.md`: Updated capability matrix and invariant mapping to mark Causal Graph / Reference Trace as Supported.
- Key decisions & rationale:
  * Relational SQLite references: implemented causal tracing using indexed SQLite relationships and DAG cycle checks without introducing a graph database, microservice, or external daemon.
  * Distinct causation vs ledger order: separates `entry_hash`/`prev_hash` sequential ledger chain from directional causal dependencies (`caused_by`, `verifies`, `derived_from`, `triggers`, `part_of`).
  * Fail-closed DAG enforcement: rejects cyclic links (`CycleDetectedError`) at persistence time before commit.
  * Clear authority labels in timeline: timeline explicitly tags provenance authority (`caller_asserted`, `policy_kernel`, `operator_human`, `executor_observed`, `verifier_observed`).
- Validation:
  * All 137 tests passing with 0 failures (`uv run pytest -m "not slow"`).
  * `uv run ruff check core executors gateway sdk cli tests examples` passes with 0 issues.
  * `uv run mypy core executors gateway sdk cli tests/unit/test_causal_trace.py tests/unit/test_observations.py` passes with 0 issues.

### 2026-11-17 15:30 IST

- Implemented Phase 4 (Constrained Cross-Agent Handoff Experiment) according to PLAN_V4.md.
- Files modified/created:
  * `spec/handoff.v1.schema.json`: Formal JSON Schema for version 1 task handoff records with initiator, assigned, verifier agent IDs, allowed verbs/resources, assertion claims, and prior crossings.
  * `core/actentra_core/handoffs.py`: Implemented `TaskHandoffRecord`, canonical `compute_handoff_hash`, `build_handoff`, caller authorization validation (`validate_caller`), scope permission checking (`is_action_permitted`), and error types (`UnauthorizedAgentHandoffError`, `ExpiredHandoffError`, `ContradictionDetectedError`).
  * `core/actentra_core/receipts.py`: Added `task_handoffs` table with indexes on `task_id`, `(assigned_agent_id, status)`, and `status`; added `record_handoff`, `get_handoff`, `get_active_handoff_by_task`, `list_handoffs`, `update_handoff_status`, and `count_handoffs`.
  * `core/actentra_core/causal.py`: Enhanced causal trace builder to recognize `task_handoffs` as first-class nodes in the causal DAG and timeline.
  * `core/actentra_core/__init__.py`: Exported handoff models, functions, and exceptions.
  * `gateway/actentra_gateway/services.py`: Added `create_task_handoff`, `get_task_handoff`, `list_task_handoffs`, `advance_task_handoff`, and `verify_task_handoff` to `AppServices`; populated `executed` and `outcome` status on dispatched crossings; exported handoffs in `export_audit_bundle`.
  * `gateway/actentra_gateway/http_service.py`: Added REST endpoints (`POST /v1/handoffs`, `GET /v1/handoffs`, `GET /v1/handoffs/{id}`, `POST /v1/handoffs/{id}/advance`, `POST /v1/handoffs/{id}/verify`).
  * `cli/actentra_cli/main.py`: Added `handoff` CLI command group (`actentra handoff create`, `advance`, `verify`, `show`, `list`) with JSON support and `actentra demo-handoff` (`actentra demo --handoff`).
  * `gateway/actentra_gateway/demo.py`: Implemented 7-step cross-agent handoff demonstration `run_handoff_demonstration()` simulating Planner (Agent A), Builder (Agent B), Auditor (Agent C), unauthorized interloper rejection, drift contradiction detection, and gateway restart survival.
  * `tests/unit/test_handoffs.py`: Added 8 comprehensive unit tests covering record validation, hash integrity, caller authorization, scope checking, advancement lifecycle, independent verification and drift detection, REST APIs, and end-to-end demonstration.
  * `docs/product-status.md`: Updated capability matrix and invariant evidence matrix to reflect Cross-Agent Task Continuity & Handoffs as Supported.
- Key decisions & rationale:
  * Principle of Least Authority across agents: downstream agents operate strictly within the bounded verbs and resources granted by the predecessor handoff.
  * Independent verification (Verifier role): handoff assertions are verified against real disk state by an independent verifier agent (`agent_auditor`) using `WorkspaceFileVerifier` rather than trusting predecessor claims.
  * Explicit drift contradiction detection: if state changes out-of-band or hashes drift, status updates to `contradicted` and handoff is blocked.
  * Restart-safe persistence: all handoffs, advances, and contradictions are stored in SQLite and survive complete gateway process restarts.
- Validation:
  * All 145 tests passing with 0 failures (`uv run pytest -m "not slow"`).
  * `uv run ruff check core executors gateway sdk cli tests examples` passes with 0 issues.
  * `uv run mypy core executors gateway sdk cli tests/unit/test_handoffs.py tests/unit/test_causal_trace.py tests/unit/test_observations.py` passes with 0 issues.
