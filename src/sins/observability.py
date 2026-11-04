"""Structured logging, request IDs and in-process metrics.

No external dependencies: metrics are collected in process memory and
`/metrics` exports them in Prometheus text format. When multiple instances
run, Prometheus scrapes each instance separately.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

_request_id: ContextVar[str] = ContextVar("sins_request_id", default="-")

# Fields attached to log records as extra attributes.
_EXTRA_FIELDS = (
    "event",
    "tenant_id",
    "scan_id",
    "engine",
    "method",
    "path",
    "status_code",
    "duration_ms",
)


# --------------------------------------------------------------------------
# Request ID
# --------------------------------------------------------------------------


def request_id() -> str:
    return _request_id.get()


def set_request_id(value: str) -> None:
    _request_id.set(value)


def new_request_id() -> str:
    return uuid.uuid4().hex[:16]


def sanitize_request_id(raw: str | None) -> str | None:
    """Sanitizes an ID received from an external header.

    Only up to 64 alphanumeric/-/_ characters are accepted — prevents log injection.
    """
    if not raw:
        return None
    cleaned = "".join(ch for ch in raw.strip() if ch.isalnum() or ch in "-_")
    return cleaned[:64] or None


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------


class JsonFormatter(logging.Formatter):
    """Each log record is a single JSON line (for log aggregators)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": _request_id.get(),
        }
        for field in _EXTRA_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class TextFormatter(logging.Formatter):
    """Readable format for dev, with request_id."""

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        rid = _request_id.get()
        return f"{base} [rid={rid}]" if rid != "-" else base


def configure_logging(level: str | None = None) -> None:
    """Configures the root logger once (idempotent)."""
    log_level = (level or os.environ.get("SINS_LOG_LEVEL", "INFO")).upper()
    as_json = os.environ.get("SINS_LOG_JSON", "1").lower() not in {"0", "false", "no"}

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        JsonFormatter()
        if as_json
        else TextFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(log_level)

    # Prevent Uvicorn's own handlers from writing duplicates.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers = []
        logger.propagate = True


# --------------------------------------------------------------------------
# Metrikalar
# --------------------------------------------------------------------------


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _label_key(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    pairs = sorted(labels.items())
    return ",".join(f'{name}="{_escape_label(str(value))}"' for name, value in pairs)


def _fmt_labels(labels: str) -> str:
    return f"{{{labels}}}" if labels else ""


class MetricsRegistry:
    """Minimal, thread-safe counter/gauge/summary registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, str], float] = {}
        self._gauges: dict[tuple[str, str], float] = {}
        self._summary_count: dict[tuple[str, str], int] = {}
        self._summary_sum: dict[tuple[str, str], float] = {}

    def inc(self, name: str, labels: dict[str, str] | None = None, value: float = 1.0) -> None:
        key = (name, _label_key(labels or {}))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + value

    def gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = (name, _label_key(labels or {}))
        with self._lock:
            self._gauges[key] = value

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = (name, _label_key(labels or {}))
        with self._lock:
            self._summary_count[key] = self._summary_count.get(key, 0) + 1
            self._summary_sum[key] = self._summary_sum.get(key, 0.0) + float(value)

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._summary_count.clear()
            self._summary_sum.clear()

    def render(self) -> str:
        lines: list[str] = []
        with self._lock:
            counters = sorted(self._counters.items())
            gauges = sorted(self._gauges.items())
            summary_count = sorted(self._summary_count.items())
            summary_sum = dict(self._summary_sum)

        seen: set[str] = set()
        for (name, labels), value in counters:
            if name not in seen:
                lines.append(f"# TYPE {name} counter")
                seen.add(name)
            lines.append(f"{name}{_fmt_labels(labels)} {value:g}")

        for (name, labels), value in gauges:
            if name not in seen:
                lines.append(f"# TYPE {name} gauge")
                seen.add(name)
            lines.append(f"{name}{_fmt_labels(labels)} {value:g}")

        for (name, labels), count in summary_count:
            if name not in seen:
                lines.append(f"# TYPE {name} summary")
                seen.add(name)
            total = summary_sum.get((name, labels), 0.0)
            lines.append(f"{name}_count{_fmt_labels(labels)} {count}")
            lines.append(f"{name}_sum{_fmt_labels(labels)} {total:g}")

        return "\n".join(lines) + ("\n" if lines else "")


METRICS = MetricsRegistry()


def track_scan_started() -> None:
    METRICS.inc("sins_scans_started_total")


def track_scan_finished(status: str, duration_ms: int, findings: int) -> None:
    METRICS.inc("sins_scans_finished_total", {"status": status})
    METRICS.observe("sins_scan_duration_ms", duration_ms)
    METRICS.inc("sins_findings_total", {"source": "scan"}, float(findings))


def track_engine(name: str, ok: bool, duration_ms: int) -> None:
    METRICS.inc("sins_engine_runs_total", {"engine": name, "ok": str(ok).lower()})
    METRICS.observe("sins_engine_duration_ms", duration_ms, {"engine": name})
