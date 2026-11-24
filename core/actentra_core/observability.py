"""Operational observability and telemetry for Actentra.

Phase 7: Production Reliability Engineering.
Provides thread-safe operational metrics collection, failure counters, latency
measurement, and structured security event logging without sensitive data leakage.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from typing import Any

logger = logging.getLogger("actentra.ops")

_SENSITIVE_KEY_NAMES = frozenset(
    {
        "token",
        "secret",
        "password",
        "credential",
        "api_key",
        "authorization",
        "bearer",
        "private_key",
    }
)


def sanitize_operational_data(data: Any) -> Any:
    """Recursively scrub known sensitive field names from operational structures."""
    if isinstance(data, dict):
        cleaned: dict[str, Any] = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in _SENSITIVE_KEY_NAMES):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = sanitize_operational_data(v)
        return cleaned
    elif isinstance(data, (list, tuple)):
        return [sanitize_operational_data(x) for x in data]
    return data


class OperationalMetrics:
    """Thread-safe operational telemetry and health metrics collector."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = defaultdict(int)
        self._latencies: dict[str, list[float]] = defaultdict(list)
        self._max_latency_samples = 200
        self._start_time = time.time()

    def increment(self, metric_name: str, count: int = 1) -> None:
        """Increment a monotonically increasing operational counter."""
        with self._lock:
            self._counters[metric_name] += count

    def record_latency(self, operation: str, duration_seconds: float) -> None:
        """Record an operation latency sample (in seconds)."""
        duration_ms = max(0.0, duration_seconds * 1000.0)
        with self._lock:
            samples = self._latencies[operation]
            samples.append(duration_ms)
            if len(samples) > self._max_latency_samples:
                # Keep most recent samples
                self._latencies[operation] = samples[-self._max_latency_samples :]

    def get_counter(self, metric_name: str) -> int:
        """Get current value of a counter."""
        with self._lock:
            return self._counters.get(metric_name, 0)

    def snapshot(self) -> dict[str, Any]:
        """Return a structured, sanitized snapshot of all operational metrics."""
        with self._lock:
            counters = dict(self._counters)
            latencies_summary: dict[str, dict[str, float]] = {}
            for op, samples in self._latencies.items():
                if samples:
                    sorted_samples = sorted(samples)
                    p50_idx = int(len(sorted_samples) * 0.50)
                    p95_idx = min(len(sorted_samples) - 1, int(len(sorted_samples) * 0.95))
                    p99_idx = min(len(sorted_samples) - 1, int(len(sorted_samples) * 0.99))
                    latencies_summary[op] = {
                        "count": len(samples),
                        "avg_ms": round(sum(samples) / len(samples), 2),
                        "p50_ms": round(sorted_samples[p50_idx], 2),
                        "p95_ms": round(sorted_samples[p95_idx], 2),
                        "p99_ms": round(sorted_samples[p99_idx], 2),
                        "max_ms": round(sorted_samples[-1], 2),
                    }

        uptime_seconds = round(time.time() - self._start_time, 1)

        return {
            "uptime_seconds": uptime_seconds,
            "crossings": {
                "total": counters.get("crossings_total", 0),
                "allowed": counters.get("crossings_allowed", 0),
                "denied": counters.get("crossings_denied", 0),
                "asked": counters.get("crossings_asked", 0),
                "held": counters.get("crossings_held", 0),
            },
            "executions": {
                "dispatched": counters.get("executions_dispatched", 0),
                "succeeded": counters.get("executions_succeeded", 0),
                "failed": counters.get("executions_failed", 0),
                "unknown": counters.get("executions_unknown", 0),
            },
            "idempotency": {
                "registered": counters.get("idempotency_registered", 0),
                "cached_hits": counters.get("idempotency_cached_hits", 0),
                "conflicts": counters.get("idempotency_conflicts", 0),
                "in_flight_blocks": counters.get("idempotency_in_flight_blocks", 0),
                "reconciliation_required": counters.get("idempotency_reconciliation_required", 0),
            },
            "lifecycle": {
                "transitions_total": counters.get("lifecycle_transitions_total", 0),
                "invalid_transitions_blocked": counters.get(
                    "lifecycle_invalid_transitions_blocked", 0
                ),
                "reconciliations": counters.get("lifecycle_reconciliations", 0),
            },
            "storage": {
                "db_retries": counters.get("storage_db_retries", 0),
                "db_errors": counters.get("storage_db_errors", 0),
                "integrity_checks_passed": counters.get("storage_integrity_checks_passed", 0),
                "integrity_checks_failed": counters.get("storage_integrity_checks_failed", 0),
                "recoveries_completed": counters.get("storage_recoveries_completed", 0),
            },
            "latencies": latencies_summary,
        }

    def reset(self) -> None:
        """Reset all metrics (primarily for test isolation)."""
        with self._lock:
            self._counters.clear()
            self._latencies.clear()
            self._start_time = time.time()


# Process-wide default metrics collector
_GLOBAL_METRICS = OperationalMetrics()


def get_global_metrics() -> OperationalMetrics:
    """Return the global default operational telemetry collector."""
    return _GLOBAL_METRICS
