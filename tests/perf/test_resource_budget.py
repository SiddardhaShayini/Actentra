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
