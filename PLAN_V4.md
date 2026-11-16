<p align="center">
  <img src="assets/actentra-logo-dark.svg" alt="Actentra" width="260" />
</p>
# Actentra — Project Analysis & Strategic Plan V4

**Prepared:** 2026-11-16  
**Scope:** Static inspection of the repository and a proposed, incremental roadmap. No commands, tests, builds, services, installs, or source changes were performed for this analysis.

## Executive summary

Actentra already has a substantial local-first authorization and execution boundary. Its Python kernel canonicalizes proposed tool actions, computes deterministic risk tags, evaluates deny-by-default YAML policies, supports human approval, dispatches through scoped filesystem/SQLite/HTTP executors, and records decisions and outcomes in a SQLite hash chain. Developers can integrate through the Python SDK, adapters, MCP stdio proxy, HTTP gateway, and CLI. Persistent approval records, audit views, policy simulation, and an embedded operator console are also present.

The project’s defining job should remain:

> **Decide whether an action may happen, constrain how it happens, and record what the execution path reported.**

The research question—whether an intended real-world state exists, remains valid, and has credible proof—can extend this purpose, but it is not implemented today. The right next step is not a broad “world model,” distributed graph, or multi-agent platform. It is to first make action identity, lifecycle state, evidence quality, and restart semantics explicit, then add a small, read-only state-observation layer using the existing SQLite and executor architecture.

### Recommended direction

1. **Essential:** Align the lifecycle contract, supported-feature claims, identity/provenance semantics, and restart/recovery behavior with the current source.
2. **Demonstrate:** Use the existing HTTP gateway, `AppServices`, filesystem executor, SQLite approvals, receipts, and console for an end-to-end approval-and-audit demonstration.
3. **High value:** Add a narrowly scoped, independently invoked state observation for one resource type (initially workspace files). Store compact, provenance-labeled observations and their freshness, not an unrestricted copy of system state.
4. **Later research:** Represent causal links as typed references in SQLite; treat the graph as a view over the audit/evidence records. Prototype cross-agent handoff only after identity and evidence references are trustworthy.

Do not add an inference dependency to the policy kernel. A hosted small model may optionally propose tool calls in a demo; its output remains untrusted input. The deterministic Actentra path—not model judgment—must decide authorization. No local GPU, large local model, Docker stack, vector database, or new server is required for the proposed initial work.

## 1. Scope and confidence

This assessment is based on the checked-in source, tests, documentation, schemas, and configuration, including [README.md](README.md), [PLAN_V3.md](PLAN_V3.md), [PROJECT_MEMORY.md](PROJECT_MEMORY.md), [docs/product-status.md](docs/product-status.md), [docs/lifecycle-contract.md](docs/lifecycle-contract.md), and implementation modules referenced below. Claims about current behavior are static source observations, not results from running the program. Test files are cited as evidence that coverage exists, not as proof that tests passed in this task.

There are differing levels of evidence:

- **Present in source:** A module or API exists.
- **Integrated in a path:** The relevant source path calls it.
- **Tested:** A test file asserts a behavior.
- **Independently verified:** Evidence is produced by a verifier that does not merely repeat the initiating agent’s claim.

These are not interchangeable. In particular, a caller-provided outcome hash is not independent proof of an external action, and a local hash chain is not an external trust anchor.

## 2. Existing architecture and capabilities

### 2.1 Architecture and request flow

Actentra is a modular Python application, with a deterministic core and several integration surfaces:

1. **Agent or caller:** Proposes a tool, verb, resource, parameters, and optional declared intent/provenance.
2. **Integration boundary:** The Python `Boundary`, function-calling/LangChain adapters, MCP proxy, or HTTP gateway receives the proposal.
3. **Envelope and canonicalization:** [envelope.py](core/actentra_core/envelope.py) constructs an `ActionEnvelope`; [canonicalize.py](core/actentra_core/canonicalize.py) normalizes supported resources and JSON values and computes hashes.
4. **Deterministic policy:** [policy.py](core/actentra_core/policy.py) evaluates risk, policy rules, rate limits, budgets, and the kill switch. The default verdict is required to be fail-closed (`deny` or `hold`).
5. **Approval and dispatch:** `ASK` actions can be persisted for human resolution. Allowed actions may run through a registered scoped executor or a user-supplied SDK callable.
6. **Audit:** [receipts.py](core/actentra_core/receipts.py) stores decision and outcome records in SQLite WAL, chains record hashes, stores action envelopes, and stores pending approvals.
7. **Operator and developer tools:** [services.py](gateway/actentra_gateway/services.py) shares application operations; [http_service.py](gateway/actentra_gateway/http_service.py) exposes a loopback-first REST API and embedded console; [main.py](cli/actentra_cli/main.py) provides CLI workflows.

The normative lifecycle is documented in [lifecycle-contract.md](docs/lifecycle-contract.md). The most relevant source entry points are `Boundary.execute()` in [boundary.py](sdk/python/actentra/boundary.py), `AppServices.submit_crossing()` / `execute_approved_crossing()` in [services.py](gateway/actentra_gateway/services.py), and `ActentraHTTPHandler.do_POST()` in [http_service.py](gateway/actentra_gateway/http_service.py).

### 2.2 Existing capabilities (observed in source)

| Area | Existing implementation | Practical assessment |
|---|---|---|
| Authorization and policy | YAML parsing/validation, deny-overrides verdict precedence, deterministic risk tags, rate limits, per-session budgets, shadow mode, freeze/unfreeze, and last-known-good policy reload in [policy.py](core/actentra_core/policy.py), [risk.py](core/actentra_core/risk.py), and [budgets.py](core/actentra_core/budgets.py). | Strong foundation for deterministic authorization; session identity and in-memory state semantics still need to be documented and tested across boundaries/restarts. |
| Action identity | Versioned envelope, stable action payload hash, Windows-aware path normalization, resource globs, URL-related canonicalization, and cross-language test vectors in [envelope.py](core/actentra_core/envelope.py), [canonicalize.py](core/actentra_core/canonicalize.py), and [canonical_test_vectors.json](spec/canonical_test_vectors.json). | Hash binds the action/session/agent ID, but not every context field such as provenance and intent. The vectors describe a deterministic subset, not full RFC 8785 conformance. |
| Execution | Workspace-confined filesystem tools in [fs.py](executors/actentra_executors/fs.py), a parameterized single-statement SQLite executor in [sqlite.py](executors/actentra_executors/sqlite.py), and host/method/size/redirect-constrained HTTP in [http.py](executors/actentra_executors/http.py). | Useful first-party reference executors. These do not replace OS isolation or mediate tools an agent can invoke outside Actentra. |
| SDK and integrations | `Boundary` and `@guard` in [boundary.py](sdk/python/actentra/boundary.py); function-calling and LangChain wrappers in [function_calling.py](sdk/python/actentra/adapters/function_calling.py) and [langchain.py](sdk/python/actentra/adapters/langchain.py); MCP stdio mediation and tool-definition pinning in [mcp_proxy.py](gateway/actentra_gateway/mcp_proxy.py). | Multiple adoption paths exist. Their mapping of tool names, identity, context, approval, and execution outcomes must stay aligned. |
| Gateway and operator surface | `ExecutorRegistry`, `AppServices`, approval lifecycle, receipt queries, verification, export, policy simulation/canary, and embedded multi-view UI in [services.py](gateway/actentra_gateway/services.py), [http_service.py](gateway/actentra_gateway/http_service.py), and [console.html](gateway/actentra_gateway/console.html). | Already sufficient for a lightweight demonstration. Gateway starts loopback by default; non-loopback binding is explicitly gated and requires a token, but the built-in server is plain HTTP. |
| Durable audit | Decision/outcome records, an append hash chain, action-envelope storage, unique outcome index, pending approval records, paged queries, streaming record iteration/export/verification, archive operations, signed checkpoints, and HTML reports in [receipts.py](core/actentra_core/receipts.py), [checkpoints.py](core/actentra_core/checkpoints.py), and [reporting.py](core/actentra_core/reporting.py). | Good local audit foundation. Receipt integrity and evidence of the external world are different claims. Signed checkpoints need an independently protected/distributed copy to anchor against full local database rewriting. |
| Risk rehearsal and supporting material | Dry-run, policy canary, replay corpora, JSON Schemas, CLI, and test suites under [canary.py](core/actentra_core/canary.py), [corpus/](corpus/), [spec/](spec/), [main.py](cli/actentra_cli/main.py), and [tests/](tests/). | Valuable for policy iteration. Canary is advisory until its exact replay context and state semantics are validated; the test suite was not executed for this plan. |
| Dependencies and runtime | Python `>=3.12`, PyYAML, `cryptography`, and Typer; built-in `sqlite3`, `http.server`, and `urllib` are used in [pyproject.toml](pyproject.toml). Windows CI is configured in [ci.yml](.github/workflows/ci.yml). | A small dependency footprint is aligned with the laptop constraint. Preserve it unless a concrete use case justifies another dependency. |

### 2.3 Existing persistence versus process-local state

The following distinction is central to a restart demonstration:

- **Persisted:** SQLite decision/outcome receipts, action envelope JSON, and pending approval state (including status and expiry) in `ReceiptStore`.
- **Process-local:** `Boundary` session taint, policy rate-limit buckets, cumulative budget tracker, freeze state, and `WarrantRegistry` use counters.
- **Recovery helpers:** `ReceiptStore.recover_pending_outcomes()` and `recover_pending_approvals()` exist, but source search found no production startup call sites. Do not claim automatic recovery merely because helper methods exist.

There is an important recovery design question: `recover_pending_outcomes()` scans allowed decisions without outcomes. A decision-only crossing may intentionally be awaiting an external executor to report its outcome. Automatically marking every such crossing `unknown` on restart would conflict with that supported external-reporting workflow. Before adding automatic recovery, distinguish “authorized/not dispatched” from “dispatch started/outcome uncertain,” then recover only crossings whose execution could actually have been in flight.

## 3. Limitations, technical debt, and improvement opportunities

### 3.1 Evidence and trust limitations

1. **No persistent representation of actual world state exists.** Current receipts capture authorization and an execution outcome/hash; there is no state inventory, expected-state assertion, freshness policy, independent verifier, or state version history.
2. **Outcome does not always mean verified effect.** For an Actentra-registered executor, `_dispatch_and_record()` records a success outcome and hashes the returned result. For external execution, `record_external_outcome()` accepts a caller-reported status/hash and labels it `caller-reported`. The latter proves what was submitted to Actentra, not what a separate system actually did.
3. **A result hash is compact integrity metadata, not evidence by itself.** It does not preserve the result content, identify an independent observer, describe verification method, or guarantee that the reported state remains true.
4. **Envelope context is only partially bound.** `compute_action_hash()` covers envelope version, session ID, agent ID, and action. It does not include provenance or declared intent. `get_envelope(verify_integrity=True)` recomputes the action hash; changes to context outside that hash can therefore evade that specific integrity check. Approval displays and policy decisions can depend on context, so context binding should be resolved before trust-sensitive continuity claims.
5. **Gateway identity/context are caller assertions.** `AppServices.submit_crossing()` accepts request-supplied `session_id`, `agent_id`, and provenance. On the local loopback deployment this may be an acceptable single-user trust assumption, but these values are not authenticated principals. A model or untrusted remote caller must not define its own trusted identity or evidence grade.
6. **The receipt chain is local tamper evidence.** A host administrator able to rewrite the database can recompute a local chain. Signed checkpoints help only when the signing key and a checkpoint copy are protected independently from the database.

### 3.2 Lifecycle and reliability limitations

- Approval persistence across process recreation is covered in [test_app_services.py](tests/unit/test_app_services.py), and approval execution is exercised with registered executors. That does not automatically prove crash recovery, idempotent external side effects, or restoration of all process-local controls.
- Persisted approvals survive restart, but budgets, taint, freeze, rate-limit history, and warrant-use counters do not. Any guarantee that requires those to span restarts needs an explicit scope and persistence design.
- `Boundary`, MCP, and HTTP gateway have different execution mechanics. Keep one contract for identity, authorization, approval, dispatch, failure, and evidence classification.
- The MCP proxy pins tool definitions within its process. That in-memory pin is not itself durable continuity across process restarts.
- The audit/UI surface is broad for a small project. Keep the existing embedded UI and `AppServices`; do not introduce a frontend framework or separate service just to add evidence views.

### 3.3 Scale, resource, and documentation limitations

- SQLite WAL, bounded HTTP bodies (2 MiB), and bounded receipt page size (up to 500) fit a local single-operator product. `ThreadingHTTPServer` is thread-per-request rather than an explicitly bounded worker pool; high concurrency is not the current target.
- Some paths can materialize full histories: `iter_records()` returns a list; audit-bundle export collects all records; canary replay also reads a full record list. Streaming verification/export exists, but these other paths need either explicit size limits, streaming implementations, or documented small-history expectations before large logs are a target.
- Current receipt records are compact, but action parameters and envelope JSON are retained. Evidence work must consider privacy, secret redaction, retention, and export rather than storing arbitrary state snapshots.
- Product and planning materials have drifted: [README.md](README.md) and [docs/product-status.md](docs/product-status.md) describe a wide feature set; older summaries in [PROJECT_MEMORY.md](PROJECT_MEMORY.md) and [PLAN.md](PLAN.md) still describe earlier phases. [REVIEW.md](REVIEW.md) and portions of [PLAN_V3.md](PLAN_V3.md) contain findings that are stale relative to current source—for example, the current approval route requires a JSON boolean, and current HTTP redirect handling validates destinations. Treat older reviews as historical context, not as a current source of truth.
- “Supported” should mean a precisely stated behavior with maintained end-to-end test evidence, not merely a module or unit test.

### 3.4 What to keep, improve, and defer

**Keep:** Deterministic policy enforcement, deny-by-default behavior, the existing Python layering, scoped first-party executors, SQLite, SDK/CLI/MCP/gateway surfaces, persistent approvals, hash-chained receipts, and a local operator console.

**Improve:** Lifecycle/restart semantics, authenticated or explicitly trusted identity assignment, full context binding, outcome/evidence labeling, operator understanding of “approved / dispatched / completed / independently verified,” and memory-bounded audit paths.

**Defer:** Enterprise SSO, multi-tenancy, remote control plane, distributed event/graph database, vector database, general-purpose world model, autonomous approval agent, broad connector expansion, and desktop shell. None is needed for the proposed demonstration or a first evidence experiment.

## 4. Strategic research directions

Scores are planning judgments, not proof of novelty or user demand. “Originality” refers to the project’s combination and execution, not a claim that the individual concepts are new.

| Direction | Feasibility | Practical value | Originality potential | Complexity | Recommendation |
|---|---:|---:|---:|---:|---|
| **A. Verifiable World State** | Medium-high for a narrow resource; low for a universal model | High where actions have important postconditions | Moderate: the value is linking deterministic authorization to independently checkable, fresh evidence | Medium for a bounded filesystem/API verifier; high for generic state modeling | **Primary research direction**, beginning with one resource type and explicit trust/freshness bounds. |
| **B. Cross-Agent Continuity** | Medium after identity and event references are reliable | Medium-high for multi-step tasks and independent verification | Moderate; continuity is more credible when agents consume verifiable references rather than natural-language memory | Medium-high due to identity, handoff consistency, revocation, provenance, and trust separation | **Defer as a platform feature; prototype one constrained handoff after A/C foundations.** |
| **C. Causal Execution Graph** | High for a small relational trace; low value if it becomes a general graph platform | High for debugging, audit, and proving how a state observation relates to actions | Moderate; traceability across decisions, effects, and evidence is a meaningful product-level combination | Low-medium as typed SQLite relationships; high as a general, distributed graph | **Build the minimum trace as ordinary SQLite references, not a graph database.** |

### A. Verifiable World State

**What it would mean:** A durable record of a scoped claim (“file X is absent,” “deployment Y reports version Z”), observations that test the claim, provenance for each observation, a verification method/version, uncertainty, and an expiry/freshness rule. A later observation may invalidate or supersede an earlier one.

**Why it complements Actentra:** The existing lifecycle decides whether a proposal may execute and logs an outcome. A postcondition observation would answer a different question: whether the intended effect was observed after execution and whether that observation is still fresh. It should supplement—not replace—the action policy and receipt.

**Critical limits:** The system must say *verified by which observer, against which source, at what time, under which trust assumption*. A successful local filesystem call is not a universal proof that an external workflow reached its intended result. A state may change immediately after verification. Conflicting or unavailable observations must yield `unknown`/`stale`, not a fabricated success. Do not call a same-process re-read “independent” without stating that it shares the local host and executor trust domain.

**Smallest credible experiment:** Add one Actentra-controlled, read-only verifier for workspace file existence (and, if justified, a content digest). After an authorized operation, separately invoke the verifier and persist an observation linked to the crossing. Store only the minimum fields/hash needed; do not retain file contents by default. Label a result as locally observed, not externally attested.

### B. Cross-Agent Continuity

**What it would mean:** Agent A initiates a task, Agent B continues from a small explicit handoff, and Agent C checks results independently. The handoff should reference durable task/action/evidence IDs and outstanding questions, rather than treating an agent’s free-form memory as truth.

**What exists already:** Envelopes have `agent.id`, `session_id`, and provenance; warrants can express scoped, expiring delegation; receipts persist actions and outcomes. These are useful primitives, not an end-to-end multi-agent continuity protocol.

**Missing foundations:** Gateway callers can choose submitted identity/context; in-memory taint, budgets, and warrant-use tracking reset with process state; no durable task/handoff object or revocation protocol exists; and the action hash does not bind provenance/intent. Agent IDs in a demonstration are labels unless an integration assigns them from a trusted configuration or authenticated channel.

**Practical value and risk:** Continuity can reduce repeated work, but blind transfer of claims can amplify mistakes. Agent C should receive read-only access to the evidence and independently run a verifier; it should not merely repeat Agent B’s summary. Start with one task handoff record and fixed local agent identities. Do not build general agent memory, a message broker, or an autonomous trust score.

### C. Causal Execution Graph

**What it would mean:** A trace that relates a user/task, agent proposal, policy decision, approval, dispatch, outcome, observation, and state claim with explicit causal references.

**What exists already:** Receipt sequence/hash links provide a tamper-evident *ledger order*; `crossing_id` joins decision and outcome; stored envelopes preserve action context; approval rows refer to crossings. The hash-chain’s `prev_hash` is not a causal dependency edge, and record sequence does not prove that one action produced a later state.

**Recommended implementation:** Once the event/evidence fields are defined, add typed IDs/references in SQLite (for example `caused_by_crossing_id`, `observation_id`, `task_id`, and a relation kind). Generate a graph-like timeline/view from those references. This keeps the local system inspectable and avoids graph infrastructure. Reject missing or cyclic references where the chosen relationship requires a strict DAG; do not infer causation from timestamps alone.

### Combined value and novelty

A + C form the most coherent extension: authorize an action, record an execution report, independently observe a scoped postcondition, and show how the decision/action/evidence relate. B can later consume the same task and evidence IDs. This creates a credible research progression without changing Actentra into an agent planner or a universal digital twin.

The combination could be distinctive in a local-first agent control tool, but the repository alone cannot establish market novelty, comparative advantage, or demand. Validate with a reproducible demo and user feedback before adopting “verified world state” as a broad product claim.

## 5. Proposed overall architecture

Preserve the existing path and add a compact evidence layer only after lifecycle semantics are explicit:

```text
Agent / model (untrusted proposal)
        |
Existing SDK / MCP proxy / local HTTP API
        |
ActionEnvelope -> deterministic risk + YAML policy -> DENY / HOLD / ASK / ALLOW
        |                                           |
        |                                 explicit human approval
        |                                           |
        +----------> existing scoped executor <-----+
                            |
                 decision + execution outcome
                            |
            existing SQLite receipt chain
                            |
         explicit read-only state verifier (new)
                            |
     compact observation + provenance + freshness (new)
                            |
     typed SQLite references / derived causal timeline (later)
```

### Architecture rules

- `actentra_core` stays deterministic and independent of model/provider calls.
- Keep inference optional and outside the enforcement path; neither a model nor another agent can issue its own permit.
- Use existing `AppServices`/`ExecutorRegistry`, `ReceiptStore`, JSON/YAML contracts, and embedded console before adding abstractions.
- Represent observations as a separate record type/table or a deliberately versioned receipt extension. Do not silently overload `outcome.status` to mean “world state verified.”
- Bind all policy-relevant context—particularly provenance and verifier identity/version—to an integrity-protected record before using it for replay or cross-agent trust.
- Track the distinction between decision, approval, dispatch-start, execution outcome, observation, and freshness. “Approved” is not “executed”; “success” is not necessarily “postcondition verified.”
- Treat evidence as scoped and time-bound. For mutable state, require a recheck to claim current validity.
- Avoid keeping raw contents in receipts unless the user explicitly configures it and understands the privacy/retention impact. Prefer minimal metadata and content digests.
- Keep compatibility explicit: envelope and receipt schemas currently describe v1. New durable structures need versioning, migration/unknown-field policy, and tests for old databases.

## 6. Working demonstration design

### 6.1 Minimum reliable demonstration

Use the existing local gateway and a small agent harness; do not build a new platform:

1. **Policy and workspace:** Configure `actentra serve` with a dedicated, disposable workspace and persistent `--db` file. Allow `fs.list`/`fs.read` only under that workspace. Configure `fs.delete` to return `ask` for the chosen protected demo file, with the default remaining `deny`. The existing starter policy already has an `fs.delete` approval rule and a sensitive-path deny rule; a dedicated test policy should make the intended outcome explicit.
2. **Actentra components:** `serve_cmd()` in [main.py](cli/actentra_cli/main.py) creates a `Boundary`, optional workspace executor registry, and gateway. The gateway exposes `POST /v1/crossings`, `/v1/crossings/pending`, `POST /v1/crossings/{id}/approve`, `POST /v1/crossings/{id}/execute`, `GET /v1/receipts`, `GET /v1/verify`, `/v1/bundle/export`, and `/ui`.
3. **Agent connection:** A thin client submits proposals to `/v1/crossings`. Its model-facing tool descriptions can contain only the allowed operations. The trusted harness—not the model response—sets the configured agent identity and session ID. Keep model-generated arguments and declared provenance untrusted. A small hosted model can be used optionally; a deterministic canned-call mode should remain available for repeatable tests.
4. **Allowed read:** Submit `fs.read` for a known fixture with `execute: true`. `AppServices.submit_crossing()` evaluates the action and, when allowed, dispatches through `LocalFSExecutor`; the API returns the tool result and an outcome.
5. **Protected delete:** Submit `fs.delete` for the disposable protected fixture with `execute: true`. Its `ask` decision should persist a pending approval and must not dispatch the executor. Confirm the file still exists. Rejecting should leave it untouched; explicit approval followed by execution should remove only the fixture.
6. **Denied variant:** Optionally demonstrate the default-deny path or a sensitive path. Do not use a real credential file. A separate disposable fixture avoids conflating the `ask` flow with the starter policy’s deny-overrides handling of sensitive paths.
7. **Audit:** Inspect the decision, crossing ID, policy version/rule/reason, risk tags, approval state, outcome status, result hash, sequence, and chain hash via the receipt API/console and `GET /v1/verify` (or an offline bundle). Explain that caller-reported external outcomes are labeled as such and are not independent verification.
8. **Restart:** Stop and recreate the gateway using the same policy and database path. Confirm the pending/approved approval state and existing receipt chain remain available. Verify that no action runs merely because an approval survived restart; execution still requires the explicit continuation path. Confirm the fixture’s actual state with a separate read-only check.

The current approval and executor lifecycle has coverage in [test_app_services.py](tests/unit/test_app_services.py); strict approval request validation and outcome endpoint behavior have coverage in [test_http_service.py](tests/unit/test_http_service.py). These are existing tests to extend if the demo is implemented, not commands run for this plan.

### 6.2 Agent and inference choices

- **Lowest-risk baseline:** A deterministic harness that submits a known set of tool calls. It validates Actentra integration and restart behavior without model variability or inference cost.
- **AI-agent presentation:** Put an optional thin tool-calling client in front of the same API. A Groq or other OpenAI-compatible low-cost hosted inference API can be used if current access/pricing and data handling are checked at implementation time. The provider key stays in the client’s secret store/environment and is never placed in the envelope, receipt, or prompt. Do not promise that a provider’s free tier is permanent.
- **Dependencies:** Reuse Python `urllib` or add a provider client only if it materially reduces integration complexity. No additional inference package is required for Actentra enforcement. The existing function-calling adapter wraps local callables; it does not itself call an inference provider.
- **Multiple agents:** For the initial demonstration, use separate configured agent clients or distinct harness roles (proposer, approver, verifier) with server/harness-assigned labels. Do not imply those labels are authenticated identities. Start with sequential, reproducible actions rather than parallel autonomous loops.

### 6.3 What the initial demonstration proves—and does not prove

It can demonstrate that a mediated read is allowed, a delete is held for an explicit human decision, dispatch is gated, local approval/receipt data survives process recreation, and the receipt chain verifies under the local database trust model.

It does **not** by itself prove protection from an agent that can bypass Actentra, resistance to a compromised host, independent truth about a remote system, durable budgets/taint, or end-to-end cross-agent identity. The current local receipt outcome stores a result hash rather than a general evidence bundle.

### 6.4 Additional demonstrations worth considering

1. **Taint-to-egress:** Read a deliberately untrusted fixture, then attempt an outbound request. Show the policy decision and explain that session taint currently has process-local lifetime.
2. **MCP mediation:** Place the existing stdio proxy in front of a small local MCP server; demonstrate a read, a denied call that is not forwarded, and changed tool-definition detection. This is valuable after the HTTP demo, not required for its minimum scope.
3. **Evidence freshness/drift (later):** Verify a file postcondition, modify the file outside the action, and show that the prior observation is stale or no longer supports the current claim. This needs the proposed observation layer first.
4. **Policy canary (later):** Compare a candidate policy against local receipts, clearly labeling results advisory until replay context/fidelity is independently established.

## 7. Hardware-conscious technology and model choices

The project targets Windows 11, 8 GB RAM, Intel i5, and CPU-only operation. The existing dependencies in [pyproject.toml](pyproject.toml) and SQLite/local HTTP approach are suitable for the proposed work.

| Need | Recommendation | Resource/privacy rationale |
|---|---|---|
| Policy decisions | Existing Python deterministic kernel; no LLM | Small, predictable CPU/memory use; removes model variability from authorization. |
| Persistence | Existing SQLite WAL database; small indexed observation tables if needed | No server process, Docker, external database, or vector index. |
| Agent reasoning in demo | Deterministic call script first; optional small hosted model via API for an AI-facing demo | No local model download or GPU. External prompts/tool results may leave the machine; disclose and minimize data. Provider price/free quotas can change. |
| Local development | Existing Python 3.12+ environment, standard-library networking, focused bounded fixtures | Keep current minimal runtime dependencies and avoid background workers. |
| Larger-model or GPU experiment | Not needed for Actentra’s enforcement or first demo. If later justified, notify the user first and move only that experiment to a GPU-hosted notebook such as Kaggle. | Keep code, sample data, credentials, and ordinary validation local; never silently add GPU assumptions. |

Do not run simultaneous heavy checks, local large models, Docker services, vector databases, large synthetic datasets, or load tests on the laptop by default. Measure real RSS/latency on representative local workloads before publishing targets; existing performance-test thresholds are not new independent measurements from this analysis.

## 8. Phased implementation roadmap

Estimates are rough single-maintainer planning ranges, not commitments. The phases are intentionally sequential where one establishes trust semantics needed by the next. No new runtime service is expected.

### Phase 0 — Contract and evidence baseline (about 1 week; low–medium complexity)

- **Objective/outcome:** Make the present guarantees and status precise before adding features.
- **Work:** Reconcile `PLAN_V4.md`, [docs/product-status.md](docs/product-status.md), [docs/lifecycle-contract.md](docs/lifecycle-contract.md), [README.md](README.md), and [PROJECT_MEMORY_2.md](PROJECT_MEMORY_2.md). Document caller-assigned versus trusted identity/provenance; classify executor outcomes versus caller-reported outcomes; specify which state survives restart. Define state names for proposed, evaluated, awaiting approval, approved, dispatch started, outcome known/unknown, observation, and stale.
- **Reuse:** Existing contract, lifecycle source/tests, receipt schemas, `AppServices`, and product matrix.
- **New dependencies/infrastructure:** None.
- **Resource impact:** Documentation and small test fixtures only; negligible.
- **Validation:** Every “supported” demo claim maps to a source path and an existing/new test. Confirm user-facing text never equates approval with execution or local hash chaining with host-compromise proof. Static documentation review; no performance claim without measurement.
- **Depends on:** None.

### Phase 1 — Restart-safe action demonstration (about 1–2 weeks; medium complexity)

- **Objective/outcome:** A repeatable demonstration with at least one agent client, an allowed read, an `ASK` deletion, human resolution, a denied variant, complete local receipt inspection, and process restart using the same DB.
- **Work:** Add a small demo harness/example and focused end-to-end coverage. Use the existing gateway APIs, `register_fs`, `ReceiptStore`, approval UI/API, and disposable workspace. Ensure harness-supplied identity and persistent `session_id` are explicit. Exercise pending and approved-but-not-yet-executed state across restart. Define whether startup calls approval cleanup; do not automatically run `recover_pending_outcomes()` until dispatch-intent semantics distinguish external pending work from uncertain in-flight execution.
- **Reuse:** [main.py](cli/actentra_cli/main.py) `serve_cmd()`, [services.py](gateway/actentra_gateway/services.py), [http_service.py](gateway/actentra_gateway/http_service.py), [fs.py](executors/actentra_executors/fs.py), [receipts.py](core/actentra_core/receipts.py), and the tests cited above.
- **New dependencies/infrastructure:** None for deterministic harness; optional hosted inference API integration with no required new Actentra dependency.
- **Resource impact:** One local gateway and SQLite DB; very low memory and CPU. No model download.
- **Validation:** Read returns expected fixture; ASK/deny produce zero executor calls before authorization; approval is explicit and one-time; after restart the expected persisted statuses and receipt sequence/hash are present; same DB passes chain and envelope verification; no unintended non-demo file changes. Include failure, expired approval, and duplicate execution cases.
- **Depends on:** Phase 0 identity/lifecycle wording.

### Phase 2 — Minimal verifiable state for one resource type (about 2–4 weeks; medium–high complexity)

- **Objective/outcome:** For one workspace-file postcondition, distinguish “execution reported success” from “Actentra’s configured verifier observed the expected state.”
- **Work:** Specify a versioned observation contract with subject/resource, observed value or digest, observation time, verifier/method version, source/trust label, uncertainty/error, freshness/expiry, and related crossing/task IDs. Implement one read-only file existence verifier (optionally content digest); persist compact observations in SQLite and expose them through existing services/UI/export. Keep raw file contents out by default. Allow `unknown`, `stale`, and conflicting outcomes.
- **Reuse:** `ActionEnvelope`, scoped filesystem containment patterns, canonical hashing, `ReceiptStore`, `AppServices`, and current audit UI/API.
- **New dependencies/infrastructure:** No new service/dependency expected; likely a SQLite schema migration and a versioned evidence/observation schema under [spec/](spec/).
- **Resource impact:** Small rows and indexed lookups; memory bounded by page/query limits. No AI inference required.
- **Validation:** Unit tests for valid/invalid observation, inaccessible/missing resource, digest mismatch, stale/future timestamp handling, tampered observation/context, privacy redaction, restart persistence, and history ordering. Integration test verifies a postcondition through a separate read-only verifier path and demonstrates subsequent drift. State explicitly that a local verifier shares the host trust boundary.
- **Depends on:** Phase 0 lifecycle/evidence contract; Phase 1 fixture and persistence patterns.

### Phase 3 — Causal trace as SQLite references (about 1–2 weeks; medium complexity)

- **Objective/outcome:** Operators can trace a state observation to its triggering proposal, policy decision, approval, execution, and task without confusing ledger order with causation.
- **Work:** Add explicit typed references and validate referential integrity; derive a compact timeline/causal view from existing receipt/approval/observation data. Preserve current receipt hash-chain semantics and version the new references. Do not add a graph database or infer causal edges from timestamps.
- **Reuse:** `crossing_id`, receipt sequence, action envelopes, approval records, observation records from Phase 2, paginated receipt APIs, offline bundle.
- **New dependencies/infrastructure:** SQLite tables/columns and schema migration only if required; no new runtime service.
- **Resource impact:** Small indexed rows; graph/timeline queries must be paged and bounded.
- **Validation:** Tests for valid linkages, missing references, wrong crossing/hash linkage, duplicate/cyclic relationships where prohibited, export/restart preservation, and an operator-readable chain matching the known demo.
- **Depends on:** Phase 2 stable observation IDs and Phase 0 lifecycle contract.

### Phase 4 — Constrained cross-agent handoff experiment (about 2–4 weeks; high complexity)

- **Objective/outcome:** Demonstrate A initiates, B continues using a durable handoff, and C independently checks the postcondition without trusting free-form prior-agent claims.
- **Work:** Add a small task/handoff record containing task ID, assigned agent identities, references to prior crossings/evidence, outstanding assertions, policy/version context, expiry, and authorization scope. Bind agent identities in the trusted harness/integration, not from model-generated fields. Give verifier C read-only evidence/state access; report contradictions and unknowns rather than silently accepting handoff claims.
- **Reuse:** Phase 2 observations, Phase 3 references, existing `agent.id`, session IDs, policy constraints, warrants only if their full lifecycle semantics are explicitly selected.
- **New dependencies/infrastructure:** SQLite persistence and one harness protocol; no message broker or multi-agent framework required for a sequential prototype. Optional hosted inference provider remains outside Actentra.
- **Resource impact:** Low local footprint; up to a few sequential API calls. External model use has network, cost, and privacy implications.
- **Validation:** A handoff survives restart; unrecognized/expired/unauthorized agent identity cannot continue; C’s verification reads the underlying configured source rather than accepting B’s text; evidence drift is detected; all operations point to the same causal trace.
- **Depends on:** Phases 0–3. Do not begin as a general continuity service before those prerequisites are reliable.

### Phase 5 — Release hardening and evidence-based expansion (ongoing; complexity driven by findings)

- **Objective/outcome:** State only the guarantees that are measured and tested for the supported local workflow.
- **Work:** Review old/new DB migration and backup/restore; test bounded audit paths at increasing but laptop-safe sizes; refine privacy/retention and operator UX; reconcile support labels; add a connector only for a demonstrated use case. Consider off-host checkpoint anchoring only if users require it and key ownership is addressed.
- **Reuse:** Existing CI, invariant-to-test matrix, [guarantees-and-limits.md](docs/guarantees-and-limits.md), [threat-model.md](docs/threat-model.md), resource tests, and CLI audit tools.
- **New dependencies/infrastructure:** None unless evidence and requirements justify one.
- **Resource impact:** Keep test sizes bounded locally; put genuinely heavy or GPU-dependent evaluation in a separately approved remote notebook/CI workflow.
- **Validation:** Supported guarantees have negative and positive lifecycle tests, restart coverage, schema compatibility checks, resource measurements, and documented residual risks. Compare claims in every public doc to the same evidence.
- **Depends on:** Demonstrated, useful phases; do not treat an experimental direction as a release prerequisite.

## 9. Risks, trade-offs, and testing strategy

| Risk/trade-off | Why it matters | Mitigation |
|---|---|---|
| “Verified” implies more than the verifier proves | A fresh local read cannot prove a remote action or protect against a hostile host. | Name the observer, source, method, scope, and timestamp; display freshness and trust domain. |
| Provenance/identity are caller controlled | Policy and agent-continuity claims may rely on fields a caller can choose. | Assign identity in trusted integration code; treat untrusted declarations as claims; integrity-bind relevant context. |
| Crash recovery confuses not-yet-dispatched with unknown execution | Existing external outcome flow permits decision-only crossings. | Persist a dispatch-start/intent transition; recover only crossings that could have executed. Keep recovery idempotent. |
| Evidence exposes sensitive data | Action parameters and evidence may contain personal, proprietary, or credential data. | Store minimized fields/digests, redact, document access/retention/export, and require opt-in for raw payload capture. |
| More record types complicate v1 compatibility | Existing envelope/receipt schemas are v1 and already consumed by APIs/tests. | Version new schemas and migrations; test old DB reads, failed migrations, and export compatibility. |
| Multi-agent labels are mistaken for authenticated principals | `agent.id` alone is descriptive, not authentication. | Use harness-assigned identity for the local demo; do not claim remote identity without authenticated principal mapping. |
| Scope grows toward graph/agent platform | More infra weakens simplicity and exceeds maintenance/resource budget. | Store typed references in SQLite; one verifier/resource type first; gate future work on user evidence. |
| Model provider costs or privacy change | Hosted inference sends prompts/tool context off-device and free tiers can change. | Keep inference optional, minimize/redact context, use user-managed credentials, and retain deterministic no-model demo mode. |

### Test strategy for future implementation

- **Core/unit:** Envelope/context hash vectors; policy verdict and approval state transitions; verifier output/freshness; evidence serialization; migration behavior.
- **Integration:** Each supported adapter through policy, approval, executor, outcome, and observation; verify denied/held calls never reach executors.
- **Restart/crash:** Reopen the same SQLite DB and verify approvals, receipts, context, and observations; simulate crash between dispatch intent and outcome; prove recovery does not close an external action that never entered dispatch.
- **Tamper and privacy:** Alter decision-linked context/evidence and require detection; verify raw secrets/content are not emitted in receipts, reports, or agent responses.
- **Concurrency/idempotency:** Two approval claims or outcome reports for one crossing dispatch/append at most once.
- **Resource:** Measure bounded HTTP request sizes, paged reads, streaming exports, canary behavior, gateway thread behavior, and RSS with controlled fixtures. Avoid large stress/fuzz jobs on the laptop by default.
- **Acceptance:** Use measurable workflows: allowed read returns expected content; unapproved delete leaves file unchanged; explicit approval affects only the exact action hash; independent verifier observes postcondition; tampering or stale evidence is surfaced, not silently accepted.

## 10. Priorities and next steps

### Essential improvements

1. Correct project status and document what is persisted, what resets, and what the current outcome fields prove.
2. Settle identity, provenance, and action-context integrity before relying on them for cross-agent trust.
3. Specify dispatch-start and crash recovery separately from approved-but-not-dispatched or externally pending crossings.
4. Deliver the gateway demonstration with a disposable workspace and real persisted DB; do not add another service.

### High-value enhancements

5. Add one bounded, read-only file-state observation with explicit source, timestamp, verifier, freshness, and integrity protection.
6. Add typed causal references and a concise trace view using SQLite.
7. Keep audit bundle/canary operations bounded for long histories and distinguish claimed from independently observed outcomes.

### Experimental research directions

8. Prototype the three-role continuity workflow only after the task/evidence references and trusted identity model are usable.
9. Evaluate a second verifier/source only when it answers a concrete user question (for example, a remote API’s authoritative read endpoint).

### Future possibilities—not now

- General-purpose world model/digital twin.
- Graph database, vector database, event-stream platform, or microservices.
- Autonomous approval/verifier agents, always-on agent teams, or local large models.
- Remote multi-tenant control plane, SSO, enterprise administration, or desktop shell.
- Additional executors without demonstrated demand and matching lifecycle tests.

**Immediate next step:** Treat Phase 0 and Phase 1 as the near-term deliverable: reconcile the lifecycle/evidence contract, then produce a reproducible local demonstration using the existing gateway and SQLite approval/receipt store. Only after that succeeds should the first state-observation contract be designed.
