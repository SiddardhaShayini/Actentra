# Incident Replay Corpus

Each entry in `agent_incidents.jsonl` maps a real-world documented AI agent failure or published vulnerability class to:

- **Failure class** (`PLAN.md` Section 3): `mistake`, `manipulation`, `over-privilege`, or `runaway`.
- **Control:** the deterministic Actentra mechanism that stops or escalates it.
- **Expected verdicts:** `deny`, `ask`, or `hold` (verified by `actentra replay` and `tests/replay/test_replay_metrics.py`).

## Documented Public References

- **EchoLeak (CVE-2025-32711):** Zero-click indirect prompt injection in Microsoft 365 Copilot via inbound email exfiltrating internal files through external HTTP requests.
- **MCP Tool Poisoning / Rug-Pull (CVE-2025-54136 & Invariant Labs research):** Malicious instructions embedded in MCP server tool metadata causing agents to read sensitive files (`.env`, `.ssh`) and exfiltrate them.
- **Replit AI Production Database Deletion (SaaStr / Jason Lemkin incident, 2025):** Over-privileged coding agent executed destructive database commands during an intended freeze without hard technical enforcement or human approval.
- **Repository / Cursor Rule Indirect Injection:** Untrusted repository config/issues inducing workspace file overwrites or credential exfiltration.
