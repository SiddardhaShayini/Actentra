# Actentra — The Execution Boundary for Autonomous AI

### Vision & Master Plan v2

**Status:** Phase 0 · **Build target:** Windows 11, Intel i5, 8 GB RAM, CPU-only · **Motto:** *Intelligence proposes. Actentra decides.*

---

## 0. What changed from the original document

| Area | Earlier draft | Current plan |
| --- | --- | --- |
| Name | Working title not cleared | **Actentra** (coined brand name; clearance still required) |
| Core idea | Execution hypervisor | Same, but defined as a **deterministic authorization + receipt layer**: no LLM in the enforcement path |
| Security model | Policies + approval | Adds **taint/provenance tracking**, **secrets broker** (agent never sees credentials), **intent binding**, **hash-chained receipts** |
| Reliability | "Production ready" (a goal) | Explicit **invariants, failure-mode table, SLOs, shadow mode, kill switch, fail-closed everywhere** |
| Hardware | "Prioritize lightweight" | Concrete **resource budgets and dev-loop rules** for 8 GB / CPU-only |
| Roadmap | 5 phases, no exit criteria | Phases with **measurable exit criteria**, week-by-week first 30 days |
| Business | Not covered | Open-core model, trademark/IP checklist, differentiation vs existing work |
| Honesty | Implied "never fails" | Honest guarantees and **explicit limits** (section 8) |

---

## 1. Project name

### 1.1 Chosen name

**Actentra** is the project's chosen working brand: a coined name evoking actions passing through a controlled entry point. Use it consistently across the product, CLI, SDK, documentation, and configuration. This is a naming decision, not a claim that the name is available or legally cleared.

### 1.2 Naming caveat (important)

A package-registry check and a web search are **not** a legal clearance. Before commercial launch or spending money on a logo or domain:

1. Search USPTO Trademark Search, the Indian Trade Marks Registry (Classes **9** software and **42** SaaS), EUIPO, and the WIPO Global Brand Database for "Actentra" and phonetic variants.
2. Check relevant domains and GitHub organization/handle availability for Actentra.
3. Check PyPI/npm names and GitHub organization availability for Actentra. Do not publish an empty placeholder package just to reserve a name; register and publish a maintained package when the project is ready.
4. Search the web, software directories, and package registries for exact and similar names in adjacent software and security categories.
5. Consult an IP attorney before filing. Trademark the **name and logo**, not the code.

### 1.3 Naming system (use consistently)

- Product: **Actentra** · Optional runtime daemon: **actentra-core** (`actentrad`) · CLI: `actentra` · Python SDK/package: `actentra` (import name `actentra`)
- Concepts: **Threshold** (a policy boundary), **Crossing** (an action request), **Verdict**, **Receipt** (signed audit record), **Warrant** (capability token, Phase 4)
- Env prefix `ACTENTRA_`, config dir `%APPDATA%\Actentra`, data dir `%LOCALAPPDATA%\Actentra`

---

## 2. Vision, mission, thesis

**Vision.** Become the standard execution boundary between probabilistic AI decisions and consequential real-world actions: what a hypervisor is to virtual machines, Actentra is to agents.

**Mission.** Turn "the model suggested it" into "the action was authorized, constrained, executed exactly as approved, and provably recorded."

**Core thesis.** Models will keep making mistakes and can be manipulated. So safety must not depend on the model behaving. Enforcement lives **outside** the model, is **deterministic**, and is **small enough to audit**. As agent autonomy grows, *authority control becomes more valuable than model intelligence.*

**The three guarantees Actentra aims to provide:**

1. **No unmediated path:** an action cannot reach a protected system except through Actentra (when deployed correctly).
2. **Executed = approved:** what runs is byte-for-byte the action that was evaluated (no TOCTOU gap).
3. **Provable history:** every decision leaves a tamper-evident receipt.

---

## 3. Problem statement (sharpened)

Agents fail in four distinct ways, and each needs a different control:

| Failure class | Example | Control |
| --- | --- | --- |
| **Mistake** | Wrong SQL `WHERE`, wrong path, wrong amount | Schema validation, constraints, dry-run, limits |
| **Manipulation** | Prompt injection in a web page or email tells agent to exfiltrate data | Taint tracking, egress rules, approval on tainted sensitive actions |
| **Over-privilege** | Agent holds a root DB credential "just in case" | Secrets broker, least-privilege warrants, per-action scope |
| **Runaway** | Loop of 10,000 API calls, escalating cost or deletes | Rate/budget limits, circuit breakers, kill switch |

Plus a fifth, organizational one: **no evidence**. When something goes wrong nobody can reconstruct what the agent did or who approved it. Receipts fix that.

---

## 4. Positioning and differentiation

This space is no longer empty. Academic and industry work already proposes runtime action authorization (for example the AARM specification for runtime action management, and research frameworks such as AgentBound, ClawLess and AgentGuardian that enforce access policies on agent tool use). Treat that as **validation of the need, and a reason to differentiate sharply**, not to ignore it. Read these papers in Phase 0 and cite them in your own docs.

**Actentra's wedge (what to be best at):**

1. **Tiny and local-first:** runs on a student laptop in <60 MB idle; no cloud, no Docker, no GPU. Most competitors assume servers.
2. **Windows-first developer experience:** many agent tools are Linux/macOS-centric; native Windows support (Job Objects, restricted tokens, Windows paths and shell semantics) is under-served.
3. **No LLM in the enforcement path:** decisions are rule-based and reproducible. An optional tiny classifier may *advise* (raise risk), never *allow* on its own.
4. **Five-minute integration:** one decorator, one MCP wrapper, one config file.
5. **Receipts as a product:** verifiable evidence you can show an auditor or a customer.
6. **Shadow mode adoption:** run observe-only first, see what *would* have been blocked, then enforce.

**Explicit non-goals (unchanged, extended):** not an LLM, chatbot, RAG framework, model trainer, workflow builder, **and not** a content/toxicity filter, a prompt firewall as the primary defense, or a replacement for OS/cloud IAM. Actentra **complements** IAM; it is the layer that understands *agent intent and context*.

---

## 5. Principles (refined)

1. **Fail closed.** Any error, timeout, corrupt policy, or unknown action type results in DENY or HOLD, never silent ALLOW.
2. **Deny by default.** Unknown tool, unknown parameter, unknown resource = denied.
3. **Deterministic core.** Same input + same policy version = same verdict. Always replayable.
4. **Canonicalize, then decide, then execute the same bytes.** Normalize paths/URLs/SQL/unicode first; hash the canonical envelope; execute only the hashed form.
5. **Least authority.** Agent gets verbs, not credentials. Actentra holds secrets and injects at execution.
6. **Small trusted core.** Keep the enforcement kernel under \~3,000 lines; everything else is a plugin that cannot weaken it.
7. **Model, framework and vendor agnostic.** Works with GPT, Claude, Gemini, Llama, Qwen, DeepSeek, local models, LangChain-style frameworks, or raw function calls.
8. **Observable and explainable.** Every verdict states *which rule* and *why*.
9. **Boring technology.** Python, SQLite, plain files. Novelty is spent on the idea, not the infrastructure.
10. **Honest guarantees.** Document exactly what is and is not protected (section 8.3).

---

## 6. Architecture

### 6.1 Request lifecycle

```
Agent / Model
   │  tool call (JSON)
   ▼
[1] Adapter (SDK decorator | MCP proxy | HTTP API)
   ▼
[2] Envelope builder → canonicalize → schema-validate → hash (action_hash)
   ▼
[3] Context & taint resolver (session, provenance labels, recent actions)
   ▼
[4] Risk engine (deterministic rules → score + tags)
   ▼
[5] Policy engine (rules + limits + budgets) → VERDICT
   ▼
      ALLOW │ ALLOW_WITH_CONSTRAINTS │ ASK (human) │ DENY │ HOLD
   ▼
[6] Approval service (only for ASK; bound to action_hash, expires)
   ▼
[7] Executor (secrets broker, dry-run, timeouts, resource limits)
   ▼
[8] Receipt writer (hash-chained, append-only) → result returned to agent (redacted if needed)
```

### 6.2 Components and V1 scope

| Component | Responsibility | In V1? |
| --- | --- | --- |
| **Interceptor/Adapters** | Capture tool calls: Python SDK decorator, HTTP `/v1/crossings`, MCP stdio proxy | In-process SDK first; optional HTTP in V1 only if resource targets are met; MCP in V2 |
| **Envelope & Canonicalizer** | Uniform action format; path/URL/SQL/unicode normalization; action hash | Yes |
| **Risk Engine** | Rule-based tags: destructive, irreversible, external-egress, privilege-escalation, bulk, financial, PII-touching | Yes (rules only) |
| **Policy Engine** | YAML rules, deny-overrides, first-match order, limits, budgets, version pinning | Yes |
| **Approval Service** | CLI prompt, local web page, webhook; approvals bound to exact action hash with expiry | CLI in V1; web/webhook V2 |
| **Executor Gateway** | Runs allowed action via connector with timeout, retries (idempotent only), redaction | One connector for the MVP; add connectors only after their boundaries are tested |
| **Secrets Broker** | Holds credentials; injects at execution; agent never sees them | Minimal (env/DPAPI) in V1 |
| **Receipt Log** | SQLite append-only + hash chain + JSONL export | Yes |
| **Shadow Mode** | Evaluate and log, never block | Yes |
| **Taint/Provenance** | Labels data as trusted/untrusted; blocks untrusted→sensitive flows | V3 |
| **Contracts / Verification** | Pre/post-conditions, invariants, policy conflict checking | V3 to V5 |
| **Sandbox** | OS-level isolation of executors | V4 |
| **Warrants (capability tokens)** | Scoped, expiring, signed authority | V4 |

### 6.3 The Action Envelope (the central data contract)

```json
{
  "envelope_version": "1",
  "crossing_id": "01J...ULID",
  "session_id": "s_abc",
  "agent": {"id": "billing-bot", "framework": "custom", "model": "any"},
  "intent": {"user_goal": "Refund order 1042", "declared_by": "human|agent"},
  "action": {
    "tool": "sql.execute",
    "verb": "write",
    "resource": "sqlite:///orders.db#refunds",
    "params": {"query": "INSERT INTO refunds ...", "args": [1042, 49.00]},
    "idempotency_key": "refund-1042"
  },
  "provenance": [{"source": "email:inbound", "trust": "untrusted"}],
  "canonical_hash": "sha256:...",
  "ts": "2026-11-12T10:00:00Z"
}
```

### 6.4 Verdicts

| Verdict | Meaning |
| --- | --- |
| ALLOW | Execute as submitted |
| ALLOW\_WITH\_CONSTRAINTS | Execute with limits (row cap, read-only transaction, redaction, dry-run first) |
| ASK | Pause; human must approve the exact `canonical_hash` |
| DENY | Refuse; return a safe, non-leaky explanation to the agent |
| HOLD | System could not decide safely (error/overload); nothing executes |

### 6.5 Policy language (V1: YAML; later: compile to a verifiable core)

```yaml
version: 1
defaults: { verdict: deny }
limits:
  - id: global-rate
    scope: session
    max_actions_per_minute: 30
rules:
  - id: fs-read-workspace
    match: { tool: fs.read, resource: "path:C:/work/**" }
    verdict: allow
  - id: sql-no-destructive
    match: { tool: sql.execute, risk_any: [destructive, irreversible] }
    verdict: ask
    reason: "Destructive SQL needs human approval"
  - id: block-egress-after-untrusted
    match: { tool: http.request, taint: untrusted, risk_any: [external-egress] }
    verdict: deny
    reason: "Untrusted content must not trigger outbound calls"
```

Rules: **deny-overrides**, explicit IDs, every verdict returns `rule_id` + `reason`. Policies are versioned, linted, unit-tested, and hot-reloaded only if validation passes (else keep last-known-good).

### 6.6 Receipts (tamper-evident audit)

Write an immutable decision record before execution, then append an outcome record (`success`, `failure`, or `unknown`) after execution. Both include `crossing_id`, `canonical_hash`, `policy_version`, verdict/rule, risk tags, timestamp, and hash-chain fields; the outcome also includes `result_hash` when available. If the process crashes mid-action, record/recover an unknown outcome rather than claiming success. No action may execute unless its decision record is durable. Add a **signed checkpoint** (Ed25519) every N records or on demand. Export as JSONL. Phase 4: optionally anchor checkpoint hashes externally (a git commit or timestamping service).

---

## 7. Resource plan for 8 GB RAM / i5 / CPU-only / Windows 11

### 7.1 Runtime budgets (enforced by automated tests)

| Metric | Budget |
| --- | --- |
| Idle daemon RSS | < 60 MB (target 40 MB) |
| Peak RSS under load (100 req/s) | < 150 MB |
| p95 decision latency (policy path) | < 10 ms; p99 < 25 ms |
| Cold start | < 1.5 s |
| Disk growth | < 1 KB per receipt average; rotation and compression built in |
| Dependencies (V1) | Prefer ≤ 12 direct deps; no torch, pandas, numpy, or Docker |
| GPU | Never required. Any ML component is optional, off by default, CPU int8, < 150 MB |

These are targets to measure on the actual Windows laptop, not guarantees of zero impact. Establish the idle baseline early. The 100 req/s load test is opt-in or CI-only, never part of the normal local development loop.

### 7.2 Technology choices (V1)

- **Python 3.12** (typed, `mypy --strict` on the core), **FastAPI + uvicorn (1 worker)**, **Pydantic v2**, **sqlite3 (WAL mode, `synchronous=NORMAL` for logs, `FULL` for approvals)**, **Typer** (CLI), **httpx**, **PyYAML**/`ruamel.yaml`, **cryptography** (Ed25519), **uv** for envs, **pytest + Hypothesis**, **ruff**.
- Use **stdlib `asyncio`** and avoid thread explosions. Single process, small thread pool.
- **Spec-first:** publish the Envelope and Policy specs as language-neutral JSON Schema so the kernel can later be rewritten in **Rust or Go** without breaking any client. Only do the rewrite when profiling proves Python is the bottleneck.

### 7.3 Dev-loop rules so the laptop never struggles

1. **No Docker Desktop and no heavy VMs in the daily loop.** If WSL2 is needed, cap it in `%UserProfile%\.wslconfig` (e.g. `memory=2GB`, `processors=2`, `swap=2GB`), because WSL2 can otherwise claim up to half of system RAM.
2. **Fast tests:** unit suite < 60 s; mark slow/fuzz/chaos tests `@pytest.mark.slow`; run them nightly or on demand, not on every save.
3. **Bound the heavy tools:** Hypothesis `max_examples` small locally, larger in CI; fuzzers time-boxed (5 to 10 minutes).
4. **Use GitHub Actions for heavy jobs** (free tier): full fuzzing, Linux sandbox tests, cross-platform matrix, security scans. Your laptop runs only the fast loop.
5. **Editor:** VS Code with the language server restricted to the repo; disable heavy extensions; close browsers with many tabs during profiling.
6. **Memory regression test** in the suite: start the daemon, push N crossings, assert RSS under budget using `psutil`.
7. **If you later add Rust:** `cargo build -j2`, use `sccache`, avoid giant dependency trees; compile in CI for releases.
8. **Test data stays small:** synthetic corpora in JSONL, no large datasets.
9. **Optional classifier (later):** distilled tiny model via ONNX Runtime CPU, quantized, lazy-loaded, with a hard memory cap. Never in the critical path of ALLOW.
10. **No surprise load:** no daemon auto-start or background load test by default; bound queues, workers, request sizes, and timeouts. Keep heavy performance tests opt-in or in CI.

### 7.4 Windows-specific engineering notes

- Use `pathlib` with explicit canonicalization: resolve `..`, short 8.3 names, UNC prefixes, drive-relative paths, alternate data streams (`file.txt:stream`), reserved names (`CON`, `NUL`), symlinks/junctions, and case-insensitivity. Path policy bugs are the most likely early security failures on Windows.
- Shell execution: prefer **argument-vector execution (no `shell=True`)**; treat `cmd.exe`/PowerShell command strings as high risk with their own parser or deny by default.
- Credentials: use **Windows DPAPI** (via `keyring`/`win32crypt`) for the V1 secrets store.
- Process limits (Phase 4): **Job Objects** (memory, CPU, process count, kill-on-close), restricted tokens, later AppContainer or WASM for stronger isolation.

---

## 8. Security and reliability engineering (the "never fails in production" section)

### 8.1 Honest framing

No real system "never fails." The goal is **fail safely, recover fast, and never fail silently open.** Everything below is designed around that.

### 8.2 System invariants (tested continuously)

- **I1:** No code path from adapter to executor bypasses the policy engine.
- **I2:** Error, timeout, unknown type, or corrupt state results in DENY/HOLD.
- **I3:** The executed action hash equals the evaluated action hash.
- **I4:** An approval is valid only for one `canonical_hash`, one session, and before expiry.
- **I5:** No action executes unless its decision record is durable; each execution attempt has an immutable outcome record, including `unknown` when its outcome cannot be established.
- **I6:** Policy changes never apply partially; invalid policy never replaces last-known-good.
- **I7:** Secrets never appear in envelopes returned to the agent, logs, or error messages.

### 8.3 Threat model

| # | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| T1 | Prompt injection triggers dangerous action | Taint tracking; deny egress/destructive on untrusted provenance; ASK escalation | Novel flows need new rules; provenance only as good as the adapter |
| T2 | Hallucinated/malformed parameters | Strict schemas, canonicalization, constraints, dry-run | Valid-but-wrong values (e.g. correct format, wrong customer) need business limits |
| T3 | Confused deputy / ambient authority | Secrets broker, per-action least privilege | Misconfigured broker scopes |
| T4 | Exfiltration through chains of benign calls | Session-level context, cumulative budgets, egress allow-lists | Slow-drip attacks; tune thresholds |
| T5 | Runaway loops, cost blowups | Rate limits, budgets, circuit breakers, kill switch | None critical if limits set |
| T6 | Log tampering | Hash chain, signed checkpoints, optional external anchoring | Attacker with full host control can delete the whole log; anchor off-host |
| T7 | Malicious plugin/connector | Plugins run out-of-process with limited API; signed plugins (Phase 4) | Supply-chain trust |
| T8 | Policy bypass via encoding, traversal, TOCTOU | Canonicalize-then-hash-then-execute-same-bytes; fuzz canonicalizers | Parser differentials between Actentra and the target system (e.g. SQL dialect quirks) |
| T9 | Compromised host or attacker edits policy | Policy file permissions/signing, separate OS user for daemon, config hash in receipts | Root-level compromise is out of scope |
| T10 | Approval fatigue / social engineering of approver | Clear diff-style approval cards, risk summary, rate-limit approvals, require re-auth for high risk | Human factors remain |

**What Actentra cannot do:** make a model correct, protect a system where agents have a direct unmediated credential, or defend against a fully compromised host. State this plainly in docs; it builds trust.

### 8.4 Failure-mode table

| Failure | Behavior | Recovery |
| --- | --- | --- |
| Daemon crash | SDK default `on_unavailable=deny`; no execution | Auto-restart (Windows service/Task Scheduler); WAL guarantees consistent DB |
| Policy file invalid | Keep last-known-good; alert; refuse new policy | Fix file, `actentra policy check`, reload |
| SQLite locked/full disk | If the decision record cannot be committed, do not execute; report the storage failure explicitly and do not claim a receipt was written | Rotate/compress logs; free space; recover and reconcile any interrupted execution as `unknown` |
| Approval service unreachable | Pending actions stay ASK/HOLD; expire after TTL | Reconnect; re-request |
| Executor timeout mid-action | Mark `unknown_outcome`; never auto-retry non-idempotent actions | Reconcile via idempotency key or manual review |
| Overload | Backpressure + 429 to agent; no queue growth beyond cap | Shed load; scale later |
| Clock skew | Monotonic counters in receipts; expiry uses daemon clock only | NTP sync warning |
| Version mismatch | Envelope version negotiation; refuse unknown major versions | Upgrade SDK or core |

### 8.5 Adoption safety features

- **Shadow mode** (observe only) → **Soft enforce** (block only top-risk) → **Full enforce**.
- **Kill switch** (`actentra freeze`): instantly deny everything except read-only allow-list.
- **Break-glass** with mandatory reason, time-boxed, double-logged.
- **Policy canary:** new policy runs in shadow against live traffic and reports differences before activation.

### 8.6 Quality strategy

- Unit tests for every rule type; **golden tests** (envelope + policy → expected verdict).
- **Property-based tests (Hypothesis):** canonicalization is idempotent; no path escapes the allowed root; verdict deterministic.
- **Fuzzing** canonicalizers (paths, URLs, SQL) and the policy parser.
- **Incident replay suite:** every real-world agent incident you collect in Phase 0 becomes a regression test.
- **Red-team corpus:** injection payloads, traversal strings, SQL tricks, unicode confusables.
- **Chaos tests:** kill daemon mid-write, fill disk, corrupt policy, drop approvals.
- **Supply chain:** pinned/locked deps, `pip-audit`, SBOM, signed releases, minimal dependency policy, reproducible builds where feasible.
- **Formal methods (late):** model the verdict state machine and approval protocol in TLA+; use an SMT solver offline in CI to detect conflicting/shadowed policy rules.

---

## 9. Roadmap with exit criteria

Assumes one developer, part-time (10 to 15 h/week). Adjust dates, keep the order.

### Phase 0 — Foundations (weeks 1 to 3)

**Deliver:** incident corpus (30 to 50 real agent failures with source links), threat model v1, Envelope spec v0 and Policy spec v0 (JSON Schema), Actentra name-clearance research, repo + license + CI skeleton, reading notes on AARM/AgentBound/ClawLess/AgentGuardian and MCP security guidance. **Exit:** every incident mapped to a failure class (section 3) and to the control that would have stopped it; clearance status documented and any naming risk resolved before commercial launch.

### Phase 1 — Kernel MVP (weeks 4 to 9)

**Deliver:** in-process Python SDK decorator, canonicalizer for the selected connector, YAML policy engine (deny-overrides), rule-based risk tags, hash-chained decision/outcome records, CLI approvals, **one narrowly scoped connector**, shadow mode, `actentra init/run/replay/verify-log`. Add the HTTP API and more connectors only after the MVP meets its resource and safety targets. **Demo:** a toy agent attempts a dangerous action within the chosen connector's supported scope; Actentra blocks or asks; the log verifies. **Exit:** incident replay ≥ 90% of dangerous actions in the supported scope blocked or escalated; false-positive rate < 5% on a benign corpus; budgets in 7.1 met; kernel < 3,000 lines.

### Phase 2 — Integration and usability (weeks 10 to 16)

**Deliver:** **MCP stdio proxy** (wrap any MCP server, intercept `tools/call`), policy lint/test CLI, local web approval UI and webhook, plugin API v0, Windows service install, static HTML/TUI report from receipts, docs site, quick-start in 5 minutes. **Exit:** two third-party agent frameworks integrated end-to-end; 5 outside testers run it; time-to-first-block < 10 minutes.

### Phase 3 — Context-aware safety (weeks 17 to 28)

**Deliver:** session context, **taint/provenance tracking**, cumulative budgets, constraints (row caps, read-only transactions, redaction), **dry-run**, idempotency + compensation actions, secrets broker v1 (DPAPI), policy canary, signed checkpoints, contracts v0 (pre/post-conditions). **Exit:** injection red-team corpus blocked ≥ 95% on defined scenarios; p95 latency still < 10 ms; documented limits published.

### Phase 4 — Isolation and identity (months 8 to 12)

**Deliver:** sandboxed executors (Windows Job Objects/restricted tokens; Linux namespaces/seccomp in CI), **Warrants** (signed capability tokens), RBAC, optional Postgres backend, multi-agent identity, plugin signing, OpenTelemetry export, hardened release process, third-party security review (even informal). **Exit:** a malicious plugin and a malicious executor script cannot exceed their limits in tests; external reviewer finds no critical bypass of I1 to I7.

### Phase 5 — Platform and enterprise (year 2+)

**Deliver:** multi-node/distributed execution, central control plane, SSO/OIDC, multi-tenancy, policy-as-code workflows (PR review of policies), compliance packs (mapping controls to frameworks such as SOC 2, ISO 27001/42001, EU AI Act record-keeping), analytics dashboard, formal verification of the kernel's critical paths, hosted offering. **Exit:** design-partner deployments; documented SLOs met for 90 days.

---

## 10. Repository layout (monorepo, small core)

```
actentra/
  spec/                 # JSON Schemas: envelope, policy, receipt, plugin API
  core/actentra_core/  # kernel: envelope, canonicalize, risk, policy, verdict, receipts
  gateway/              # FastAPI app, MCP proxy, approval endpoints
  executors/            # fs, http, sqlite, git, shell (restricted)
  sdk/python/           # actentra
  cli/                  # typer CLI
  policies/examples/    # starter policy packs
  tests/{unit,golden,property,replay,chaos,perf}/
  corpus/{incidents,benign,redteam}/
  docs/                 # architecture, threat model, guarantees & limits, quick-start
  .github/workflows/    # ci.yml (fast), nightly.yml (fuzz/slow), release.yml
```

**Rule:** `core/` has zero network and zero heavy dependencies; it is pure, deterministic, and imports nothing from `gateway/`.

---

## 11. First 30 days (concrete)

| Week | Tasks |
| --- | --- |
| 1 | Research Actentra trademark, package, domain, and GitHub availability; document clearance status before brand investment; repo + Apache-2.0 license + `SECURITY.md`; start incident corpus (aim 15) |
| 2 | Finish corpus (30+); write threat model v1 and "Guarantees and Limits" doc; read AARM + MCP security docs |
| 3 | Draft Envelope and Policy JSON Schemas; build the canonicalizer for paths only with property tests; set up CI (lint, type, fast tests) |
| 4 | Policy engine v0 (deny-overrides, 5 rule types), receipts with hash chain, `actentra verify-log`; first end-to-end demo with a fake agent |

---

## 12. Business and licensing (commercial use)

- **Model:** open-core. **Apache-2.0** for the kernel, SDK, CLI, MCP proxy (builds trust and adoption). **Commercial tier** later: SSO, multi-tenant control plane, compliance packs, long-term log retention/anchoring, support SLAs, hosted version.
- **Protect:** the **Actentra name/logo** via trademark after clearance; keep a contributor agreement (DCO or CLA) from day one so relicensing options stay open.
- **Early revenue paths:** paid design partnerships, consulting/integration, security-assessment packs for agent deployments, sponsored open-source.
- **Ideal first customers:** teams shipping agents that touch databases, cloud consoles, finance or healthcare back-ends; MCP server authors who want a safety wrapper.
- **Not legal advice:** confirm trademark, licensing and any patent questions with an IP attorney.

---

## 13. Success metrics

| Dimension | Target |
| --- | --- |
| Safety | ≥ 95% of incident-replay dangerous actions blocked/escalated by Phase 3 |
| Usability | False positives < 2% on benign corpus; time-to-first-block < 10 min |
| Performance | p95 < 10 ms; idle RSS < 60 MB |
| Reliability | 0 silent-open failures in chaos suite; every executed action has a durable decision record and an immutable outcome record |
| Adoption | 3 framework integrations, 5 outside testers (Phase 2), 3 design partners (Phase 5) |
| Trust | Public threat model, public limits, external review before 1.0 |

---

## 14. Project risks

| Risk | Mitigation |
| --- | --- |
| Scope creep (hypervisor, formal verification, distributed too early) | Phase gates; kernel size cap; defer anything not tied to an exit criterion |
| Existing specs/products or big vendors add similar guardrails | Differentiate on local-first, Windows-first, tiny footprint, receipts, shadow mode; stay interoperable (MCP, OpenTelemetry) |
| Over-claiming ("deterministic guarantee", "never fails") | Use precise language: guarantees only where invariants are tested; publish limits |
| Solo-developer burnout | Ship a demo every phase; narrow the first integration to one framework |
| Parser differentials (policy sees one thing, target system another) | Prefer structured tool interfaces over raw strings; fuzz; constrain connectors |
| Name conflict | Complete clearance before commercial launch; if a material conflict is found, pause branding and choose a cleared alternative before investing in it |
| Security bugs in your own kernel | Small core, property tests, external review, responsible-disclosure policy |

---

## 15. Decisions for you

1. **Actentra is the chosen project name.** Complete the clearance checklist in 1.2 before commercial launch or brand investment.
2. Pick the first target ecosystem for the demo: plain Python functions, MCP servers, or one agent framework.
3. Choose one narrowly scoped connector for the MVP; consider filesystem, HTTP, or SQLite only after defining its supported operations and safety limits.
4. Decide license/contribution policy now (default: Apache-2.0 + DCO).
5. Decide whether V1 ships as a local daemon, an in-process library, or both (recommended: in-process library first; no always-running daemon by default).

---

## 16. One-paragraph pitch

**Actentra** is a lightweight, local-first execution boundary for AI agents. It sits between any model and your real systems, deterministically checks every tool call against versioned policy and context, asks a human when it matters, runs the action with least privilege, and records a tamper-evident receipt. It is designed to run on a student laptop, integrate in five minutes, and avoid trusting model judgment for enforcement.
