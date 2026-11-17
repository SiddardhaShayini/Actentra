"""Audit report generation for Actentra receipt logs (HTML and summary stats)."""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from pathlib import Path

from actentra_core.receipts import ReceiptRecord, ReceiptStore, verify_log


@dataclass(frozen=True, slots=True)
class CrossingAuditItem:
    crossing_id: str
    session_id: str
    canonical_hash: str
    policy_version: str
    decision_verdict: str | None
    rule_id: str | None
    reason: str | None
    risk_tags: tuple[str, ...]
    shadow: bool
    outcome_status: str | None
    result_hash: str | None
    error: str | None
    ts: str
    decision_seq: int | None
    outcome_seq: int | None


@dataclass(frozen=True, slots=True)
class AuditSummary:
    total_records: int
    decision_count: int
    outcome_count: int
    verdict_counts: dict[str, int]
    outcome_counts: dict[str, int]
    risk_tag_counts: dict[str, int]
    rule_counts: dict[str, int]
    session_ids: tuple[str, ...]
    integrity_ok: bool
    integrity_errors: tuple[str, ...]
    head_hash: str
    start_time: str | None
    end_time: str | None
    items: tuple[CrossingAuditItem, ...] = field(default_factory=tuple)


def build_audit_summary(db_path: str | Path, *, verify_envelopes: bool = False) -> AuditSummary:
    """Analyze an Actentra receipt database and produce an immutable AuditSummary."""
    path = Path(db_path)
    store = ReceiptStore(path)
    records = store.iter_records()
    vr = verify_log(path, verify_envelopes=verify_envelopes)

    decisions_by_crossing: dict[str, ReceiptRecord] = {}
    outcomes_by_crossing: dict[str, ReceiptRecord] = {}
    verdict_counts: dict[str, int] = {}
    outcome_counts: dict[str, int] = {}
    risk_tag_counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}
    sessions: set[str] = set()

    for rec in records:
        sessions.add(rec.session_id)
        if rec.record_type == "decision":
            decisions_by_crossing[rec.crossing_id] = rec
            v = rec.verdict or "unknown"
            verdict_counts[v] = verdict_counts.get(v, 0) + 1
            r = rec.rule_id or "none"
            rule_counts[r] = rule_counts.get(r, 0) + 1
            for tag in rec.risk_tags:
                risk_tag_counts[tag] = risk_tag_counts.get(tag, 0) + 1
        elif rec.record_type == "outcome":
            outcomes_by_crossing[rec.crossing_id] = rec
            st = rec.status or "unknown"
            outcome_counts[st] = outcome_counts.get(st, 0) + 1

    # Pair crossings in order of first appearance
    seen_crossings: list[str] = []
    for rec in records:
        if rec.crossing_id not in seen_crossings:
            seen_crossings.append(rec.crossing_id)

    items: list[CrossingAuditItem] = []
    for cid in seen_crossings:
        dec = decisions_by_crossing.get(cid)
        out = outcomes_by_crossing.get(cid)
        items.append(
            CrossingAuditItem(
                crossing_id=cid,
                session_id=dec.session_id if dec else (out.session_id if out else "unknown"),
                canonical_hash=dec.canonical_hash if dec else (out.canonical_hash if out else ""),
                policy_version=dec.policy_version if dec else (out.policy_version if out else ""),
                decision_verdict=dec.verdict if dec else None,
                rule_id=dec.rule_id if dec else None,
                reason=dec.reason if dec else None,
                risk_tags=dec.risk_tags if dec else (),
                shadow=dec.shadow if dec else False,
                outcome_status=out.status if out else None,
                result_hash=out.result_hash if out else None,
                error=out.error if out else None,
                ts=dec.ts if dec else (out.ts if out else ""),
                decision_seq=dec.seq if dec else None,
                outcome_seq=out.seq if out else None,
            )
        )

    start_time = records[0].ts if records else None
    end_time = records[-1].ts if records else None

    return AuditSummary(
        total_records=len(records),
        decision_count=len(decisions_by_crossing),
        outcome_count=len(outcomes_by_crossing),
        verdict_counts=verdict_counts,
        outcome_counts=outcome_counts,
        risk_tag_counts=risk_tag_counts,
        rule_counts=rule_counts,
        session_ids=tuple(sorted(sessions)),
        integrity_ok=vr.ok,
        integrity_errors=vr.errors,
        head_hash=vr.last_hash,
        start_time=start_time,
        end_time=end_time,
        items=tuple(items),
    )


def render_html_report(
    summary: AuditSummary, *, title: str = "Actentra Execution Audit Report"
) -> str:
    """Generate a self-contained, offline HTML audit report from an AuditSummary."""
    status_color = "#10b981" if summary.integrity_ok else "#ef4444"
    status_text = "VERIFIED (TAMPER-EVIDENT OK)" if summary.integrity_ok else "VERIFICATION FAILED"

    verdict_rows = (
        "".join(
            f"<tr><td><code>{html.escape(k)}</code></td><td><strong>{v}</strong></td></tr>"
            for k, v in sorted(summary.verdict_counts.items(), key=lambda x: x[1], reverse=True)
        )
        or "<tr><td colspan='2' style='color:#6b7280'>No decisions recorded</td></tr>"
    )

    risk_rows = (
        "".join(
            f"<tr><td><span class='badge risk'>{html.escape(k)}</span></td><td>{v}</td></tr>"
            for k, v in sorted(summary.risk_tag_counts.items(), key=lambda x: x[1], reverse=True)
        )
        or "<tr><td colspan='2' style='color:#6b7280'>No risk tags triggered</td></tr>"
    )

    rule_rows = (
        "".join(
            f"<tr><td><code>{html.escape(k)}</code></td><td>{v}</td></tr>"
            for k, v in sorted(summary.rule_counts.items(), key=lambda x: x[1], reverse=True)
        )
        or "<tr><td colspan='2' style='color:#6b7280'>No rules triggered</td></tr>"
    )

    timeline_rows = []
    for it in summary.items:
        v_class = (it.decision_verdict or "none").lower()
        badge_cls = f"badge verdict-{v_class}"
        tags_html = " ".join(
            f"<span class='badge risk'>{html.escape(t)}</span>" for t in it.risk_tags
        )
        if it.outcome_status:
            out_badge = (
                f"<span class='badge status-{it.outcome_status}'>"
                f"{html.escape(it.outcome_status)}</span>"
            )
        else:
            out_badge = "<span style='color:#9ca3af'>—</span>"
        shadow_badge = " <span class='badge shadow'>SHADOW</span>" if it.shadow else ""
        cid_short = f"{html.escape(it.crossing_id[:16])}…"
        dec_v = html.escape(it.decision_verdict or "N/A")
        rule_str = html.escape(it.rule_id or "—")
        reason_str = html.escape(it.reason or "—")
        hash_title = html.escape(it.canonical_hash)
        hash_short = f"{html.escape(it.canonical_hash[:18])}…"

        timeline_rows.append(
            f"""
            <tr>
                <td><code>{cid_short}</code></td>
                <td><small>{html.escape(it.ts)}</small></td>
                <td><span class='{badge_cls}'>{dec_v}{shadow_badge}</span></td>
                <td>{out_badge}</td>
                <td><code>{rule_str}</code></td>
                <td><small>{reason_str}</small></td>
                <td>{tags_html or '<span style="color:#9ca3af">none</span>'}</td>
                <td><code title=\"{hash_title}\">{hash_short}</code></td>
            </tr>
            """
        )

    if timeline_rows:
        timeline_tbody = "\n".join(timeline_rows)
    else:
        timeline_tbody = "<tr><td colspan='8'>No records</td></tr>"

    v_allowed = summary.verdict_counts.get("allow", 0) + summary.verdict_counts.get(
        "allow_with_constraints", 0
    )
    v_denied = summary.verdict_counts.get("deny", 0)
    v_asked = summary.verdict_counts.get("ask", 0)

    css_styles = """
  :root {
    --bg: #0b0f19;
    --card-bg: #111827;
    --border: #1f2937;
    --text: #f3f4f6;
    --text-muted: #9ca3af;
    --teal: #13bfa6;
    --blue: #3b82f6;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    padding: 2rem;
    line-height: 1.5;
  }
  .container { max-width: 1280px; margin: 0 auto; }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
  }
  h1 { font-size: 1.5rem; display: flex; align-items: center; gap: 0.75rem; }
  .tagline { color: var(--text-muted); font-size: 0.875rem; margin-top: 0.25rem; }
  .grid-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }
  .stat-card {
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
  }
  .stat-label {
    color: var(--text-muted);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .stat-val { font-size: 1.75rem; font-weight: 700; margin-top: 0.25rem; }
  .status-pill {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
  }
  .tables-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 1.5rem;
    margin-bottom: 2rem;
  }
  .card {
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
  }
  .card h2 { font-size: 1rem; margin-bottom: 1rem; color: var(--text); }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { color: var(--text-muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; }
  code { font-family: "Cascadia Code", Consolas, monospace; font-size: 0.8rem; color: #93c5fd; }
  .badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
  }
  .verdict-allow { background: #064e3b; color: #6ee7b7; }
  .verdict-allow_with_constraints { background: #0e3a5a; color: #7dd3fc; }
  .verdict-ask { background: #78350f; color: #fde68a; }
  .verdict-deny { background: #7f1d1d; color: #fca5a5; }
  .verdict-hold { background: #374151; color: #d1d5db; }
  .status-success { background: #064e3b; color: #6ee7b7; }
  .status-failure { background: #7f1d1d; color: #fca5a5; }
  .status-unknown { background: #78350f; color: #fde68a; }
  .badge.risk { background: #312e81; color: #c7d2fe; }
  .badge.shadow { background: #4b5563; color: #f3f4f6; }
  .timeline-container { overflow-x: auto; margin-top: 1rem; }
  footer {
    margin-top: 3rem;
    border-top: 1px solid var(--border);
    padding-top: 1.5rem;
    font-size: 0.75rem;
    color: var(--text-muted);
    display: flex;
    justify-content: space-between;
  }
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>{css_styles}</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>
        <span style="color:var(--teal)">Actentra</span> Execution Audit Report
      </h1>
      <p class="tagline">Intelligence proposes. Actentra decides. &bull; Tamper-evident receipts</p>
    </div>
    <div>
      <span class="status-pill"
            style="background:{status_color}22; color:{status_color};
                   border:1px solid {status_color}">
        {status_text}
      </span>
    </div>
  </header>

  <section class="grid-stats">
    <div class="stat-card">
      <div class="stat-label">Total Receipts</div>
      <div class="stat-val">{summary.total_records}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Evaluated Crossings</div>
      <div class="stat-val">{summary.decision_count}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Allowed / Denied</div>
      <div class="stat-val" style="color:var(--teal)">
        {v_allowed}
        <span style="color:var(--text-muted); font-size:1.2rem">/</span>
        <span style="color:#ef4444">{v_denied}</span>
      </div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Pending / Asked</div>
      <div class="stat-val" style="color:#f59e0b">{v_asked}</div>
    </div>
  </section>

  <section class="tables-grid">
    <div class="card">
      <h2>Verdict Distribution</h2>
      <table>
        <thead><tr><th>Verdict</th><th>Count</th></tr></thead>
        <tbody>{verdict_rows}</tbody>
      </table>
    </div>

    <div class="card">
      <h2>Risk Tags Triggered</h2>
      <table>
        <thead><tr><th>Tag</th><th>Count</th></tr></thead>
        <tbody>{risk_rows}</tbody>
      </table>
    </div>

    <div class="card">
      <h2>Policy Rules Triggered</h2>
      <table>
        <thead><tr><th>Rule ID</th><th>Count</th></tr></thead>
        <tbody>{rule_rows}</tbody>
      </table>
    </div>
  </section>

  <section class="card">
    <h2>Decision & Execution Timeline</h2>
    <div class="timeline-container">
      <table>
        <thead>
          <tr>
            <th>Crossing ID</th>
            <th>Timestamp (UTC)</th>
            <th>Verdict</th>
            <th>Outcome</th>
            <th>Rule ID</th>
            <th>Reason</th>
            <th>Risk Tags</th>
            <th>Canonical Hash</th>
          </tr>
        </thead>
        <tbody>
          {timeline_tbody}
        </tbody>
      </table>
    </div>
  </section>

  <footer>
    <div>Head Hash: <code>{html.escape(summary.head_hash)}</code></div>
    <div>Actentra v0.1.0 &bull; Local-first deterministic execution boundary</div>
  </footer>
</div>
</body>
</html>
"""
