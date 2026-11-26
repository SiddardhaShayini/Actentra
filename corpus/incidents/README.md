# Incident Replay Corpus & Provenance

Each entry in `agent_incidents.jsonl` maps a real-world documented AI agent failure, published vulnerability advisory, or synthetic regression scenario to:

- **Failure class:** `mistake`, `manipulation`, `over-privilege`, or `runaway`.
- **Control:** the deterministic Actentra mechanism that stops or escalates it.
- **Expected verdicts:** `deny`, `ask`, or `hold` (verified by `actentra replay` and `tests/replay/test_replay_metrics.py`).
- **Provenance & Type:** clearly distinguishes published CVEs/advisories from synthetic benchmark test cases.

---

## 1. Documented Public CVEs and Real-World Incidents

1. **CVE-2025-32711 — Microsoft 365 Copilot EchoLeak**
   - *Source:* Microsoft Security Response Center (MSRC) / CVE-2025-32711
   - *Mechanism:* Zero-click indirect prompt injection in inbound emails triggering unauthorized outbound HTTP requests with embedded file contents.
   - *Actentra Control:* Taint propagation + strict egress policy (`block-untrusted-egress`).

2. **CVE-2025-54136 — Model Context Protocol (MCP) Tool Poisoning & Rug-Pull**
   - *Source:* Invariant Labs / CVE-2025-54136 Advisory
   - *Mechanism:* Malicious tool description injection and mid-session tool schema mutations inducing agents to harvest SSH keys and `.env` files.
   - *Actentra Control:* Invariant I3 tool-hash pinning in `MCPStdioProxy` and deny rules for `.ssh` / `.env`.

3. **Replit AI Production Database Deletion Incident (2025)**
   - *Source:* Public industry disclosure / SaaStr Report
   - *Mechanism:* Agent holding excessive write/admin database privileges issued destructive `DROP TABLE` during an intended freeze.
   - *Actentra Control:* Hard fail-closed kill switch (`Boundary.freeze()`) and mandatory `ASK` verdict on destructive SQL.

4. **Indirect Prompt Injection in Coding Agents (.cursorrules / .claude tampering)**
   - *Source:* OWASP Top 10 for LLM Applications (LLM01 / LLM02)
   - *Mechanism:* Untrusted repository files or PR context instructing the agent to overwrite local developer tool configurations or hooks.
   - *Actentra Control:* Immutable rule matching requiring explicit human approval for sensitive dotfile mutations.

---

## 2. Synthetic Benchmark Scenarios

Cases labeled as `synthetic` in `agent_incidents.jsonl` test specific edge cases in Windows path canonicalization, NTFS alternate data streams (ADS), device namespaces (`CON`, `NUL`, `\\.\PhysicalDrive0`), SQL parser differentials, and runaway recursive loops.

> **Scope Note:** Passing the incident corpus proves that Actentra enforces its defined rules against these specific test cases. It does not constitute a general mathematical proof of security against unknown attacks or host-level OS compromise.
