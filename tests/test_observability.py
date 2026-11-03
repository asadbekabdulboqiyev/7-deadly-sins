"""Kuzatuv qatlami: log formatlari, request ID sanitizatsiyasi, metrikalar."""

from __future__ import annotations

import json
import logging

import pytest

from sins.observability import (
    METRICS,
    JsonFormatter,
    MetricsRegistry,
    TextFormatter,
    new_request_id,
    sanitize_request_id,
    set_request_id,
    track_engine,
    track_scan_finished,
    track_scan_started,
)


def _record(**extra) -> logging.LogRecord:
    record = logging.LogRecord(
        name="sins.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="sinov xabari",
        args=(),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


@pytest.fixture(autouse=True)
def _reset_metrics():
    METRICS.reset()
    set_request_id("-")
    yield
    METRICS.reset()


def test_json_formatter_emits_single_valid_json_line() -> None:
    set_request_id("abc123")
    payload = json.loads(JsonFormatter().format(_record(event="boot")))

    assert payload["msg"] == "sinov xabari"
    assert payload["level"] == "info"
    assert payload["logger"] == "sins.test"
    assert payload["request_id"] == "abc123"
    assert payload["event"] == "boot"


def test_json_formatter_includes_known_extra_fields_only() -> None:
    payload = json.loads(
        JsonFormatter().format(_record(tenant_id="t1", scan_id="s1", noma_lum="yashirin"))
    )

    assert payload["tenant_id"] == "t1"
    assert payload["scan_id"] == "s1"
    assert "noma_lum" not in payload


def test_json_formatter_serializes_exception() -> None:
    try:
        raise ValueError("portlash")
    except ValueError:
        import sys

        record = _record()
        record.exc_info = sys.exc_info()

    payload = json.loads(JsonFormatter().format(record))
    assert "ValueError: portlash" in payload["exc"]


def test_text_formatter_appends_request_id() -> None:
    set_request_id("rid-42")
    line = TextFormatter("%(levelname)s %(message)s").format(_record())
    assert line.endswith("[rid=rid-42]")


def test_text_formatter_omits_placeholder_request_id() -> None:
    set_request_id("-")
    line = TextFormatter("%(levelname)s %(message)s").format(_record())
    assert "[rid=" not in line


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("abc-123", "abc-123"),
        ("  abc  ", "abc"),
        ("a b\tc", "abc"),
        ('<script>"x"</script>', "scriptxscript"),
    ],
)
def test_sanitize_request_id_keeps_safe_characters(raw: str, expected: str) -> None:
    assert sanitize_request_id(raw) == expected


def test_sanitize_request_id_truncates_to_64() -> None:
    assert len(sanitize_request_id("a" * 200) or "") == 64


@pytest.mark.parametrize("raw", [None, "", "   ", "<>\"'"])
def test_sanitize_request_id_rejects_unusable_values(raw: str | None) -> None:
    assert sanitize_request_id(raw) is None


def test_new_request_id_is_short_and_unique() -> None:
    first, second = new_request_id(), new_request_id()
    assert first != second
    assert len(first) == 16


def test_counter_renders_type_and_value() -> None:
    METRICS.inc("sins_demo_total", {"method": "GET"})
    METRICS.inc("sins_demo_total", {"method": "GET"})
    rendered = METRICS.render()

    assert "# TYPE sins_demo_total counter" in rendered
    assert 'sins_demo_total{method="GET"} 2' in rendered


def test_gauge_replaces_value() -> None:
    METRICS.gauge("sins_queue_depth", 5)
    METRICS.gauge("sins_queue_depth", 2)
    rendered = METRICS.render()

    assert "# TYPE sins_queue_depth gauge" in rendered
    assert "sins_queue_depth 2" in rendered


def test_summary_renders_count_and_sum() -> None:
    METRICS.observe("sins_demo_ms", 10)
    METRICS.observe("sins_demo_ms", 30, {"engine": "nuclei"})
    rendered = METRICS.render()

    assert "# TYPE sins_demo_ms summary" in rendered
    assert "sins_demo_ms_count 1" in rendered
    assert "sins_demo_ms_sum 10" in rendered
    assert 'sins_demo_ms_count{engine="nuclei"} 1' in rendered


def test_labels_are_escaped() -> None:
    METRICS.inc("sins_demo_total", {"path": '/a"b\\c'})
    assert 'path="/a\\"b\\\\c"' in METRICS.render()


def test_reset_clears_everything() -> None:
    METRICS.inc("sins_demo_total")
    METRICS.gauge("sins_g", 1)
    METRICS.observe("sins_s", 1)
    METRICS.reset()
    assert METRICS.render() == ""


def test_empty_registry_renders_empty_string() -> None:
    assert MetricsRegistry().render() == ""


def test_track_scan_lifecycle_records_metrics() -> None:
    track_scan_started()
    track_scan_finished("done", 1500, 7)
    rendered = METRICS.render()

    assert "sins_scans_started_total 1" in rendered
    assert 'sins_scans_finished_total{status="done"} 1' in rendered
    assert "sins_scan_duration_ms_count 1" in rendered
    assert 'sins_findings_total{source="scan"} 7' in rendered


def test_track_engine_records_ok_and_duration() -> None:
    track_engine("nuclei", True, 120)
    track_engine("nuclei", False, 5)
    rendered = METRICS.render()

    assert 'sins_engine_runs_total{engine="nuclei",ok="true"} 1' in rendered
    assert 'sins_engine_runs_total{engine="nuclei",ok="false"} 1' in rendered
    assert 'sins_engine_duration_ms_count{engine="nuclei"} 2' in rendered
