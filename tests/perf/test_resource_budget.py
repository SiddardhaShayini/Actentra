"""Lightweight resource budget checks aligned with PLAN.md Section 7.1."""

from __future__ import annotations

import os
import time
from pathlib import Path

import psutil

from actentra_core.envelope import build_envelope
from actentra_core.policy import PolicyEngine, load_policy_file

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_kernel_rss_and_decision_latency_within_budget() -> None:
    policy = load_policy_file(REPO_ROOT / "policies" / "examples" / "starter.yaml")
    engine = PolicyEngine(policy)
    env = build_envelope(tool="fs.read", verb="read", resource=r"path:C:\work\doc.txt")

    # Warm up once
    engine.evaluate(env)

    latencies_ms: list[float] = []
    for _ in range(100):
        t0 = time.perf_counter()
        engine.evaluate(env)
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)

    latencies_ms.sort()
    p95_ms = latencies_ms[94]
    rss_mb = psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)

    # PLAN.md 7.1 targets: p95 decision latency < 10 ms; idle daemon RSS < 60 MB.
    assert p95_ms < 10.0, f"p95 latency {p95_ms:.2f} ms exceeded 10 ms budget"
    # Note: pytest itself loads extra test plugins; assert generous margin under 150 MB peak
    assert rss_mb < 150.0, f"Process RSS {rss_mb:.1f} MB exceeded 150 MB"


def test_gateway_startup_and_memory_footprint(tmp_path: Path) -> None:
    from actentra import Boundary
    from actentra_core.receipts import ReceiptStore
    from actentra_gateway.http_service import create_gateway_server

    t0 = time.perf_counter()
    policy = load_policy_file(REPO_ROOT / "policies" / "examples" / "starter.yaml")
    store = ReceiptStore(tmp_path / "gateway_perf.db")
    boundary = Boundary(policy=policy, receipt_store=store)
    server = create_gateway_server(boundary, host="127.0.0.1", port=0)
    startup_ms = (time.perf_counter() - t0) * 1000.0

    try:
        health = server.services.get_health()
        assert health["status"] == "ok"
        # Startup must be snappy (under 500 ms target)
        assert startup_ms < 500.0, f"Gateway startup {startup_ms:.1f} ms exceeded 500 ms budget"
    finally:
        server.server_close()


def test_receipt_store_append_and_query_latency(tmp_path: Path) -> None:
    from actentra_core.receipts import ReceiptStore, export_jsonl
    from actentra_core.verdict import Decision, Verdict

    db_path = tmp_path / "perf_receipts.db"
    store = ReceiptStore(db_path)

    # 1. Measure decision append latency
    append_latencies: list[float] = []
    crossings = []

    for i in range(100):
        env = build_envelope(
            tool="fs.read",
            verb="read",
            resource=f"path:C:/work/file_{i}.txt",
            session_id="perf-session",
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id=f"rule-{i}",
            reason="benchmark",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )
        crossings.append((env, dec))

        t0 = time.perf_counter()
        store.record_decision(env, dec)
        append_latencies.append((time.perf_counter() - t0) * 1000.0)

    append_latencies.sort()
    p95_append = append_latencies[94]

    # SQLite WAL commits should remain fast (p95 < 25ms on local SSD/HDD)
    assert p95_append < 25.0, f"p95 append latency {p95_append:.2f} ms exceeded 25 ms"

    # 2. Record outcomes
    for env, dec in crossings:
        store.record_outcome(
            crossing_id=env.crossing_id,
            session_id=env.session_id,
            canonical_hash=env.canonical_hash,
            policy_version=dec.policy_version,
            status="success",
        )

    # 3. Measure paginated query latency
    query_latencies: list[float] = []
    for offset in (0, 20, 40, 60, 80):
        t0 = time.perf_counter()
        recs, total = store.query_records(limit=20, offset=offset)
        query_latencies.append((time.perf_counter() - t0) * 1000.0)
        assert len(recs) == 20
        assert total == 200

    query_latencies.sort()
    p95_query = query_latencies[-1]
    assert p95_query < 15.0, f"Query latency {p95_query:.2f} ms exceeded 15 ms"

    # 4. Measure streaming export latency
    t0 = time.perf_counter()
    out_file = tmp_path / "perf_export.jsonl"
    count = export_jsonl(db_path, out_file, chunk_size=50)
    export_ms = (time.perf_counter() - t0) * 1000.0
    assert count == 200
    assert export_ms < 50.0, f"Export latency {export_ms:.2f} ms exceeded 50 ms"
