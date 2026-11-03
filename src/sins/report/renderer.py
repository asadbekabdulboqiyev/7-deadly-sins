"""HTML -> PDF hisobot generatori.

Nega WeasyPrint: bir xil HTML/CSS ni brauzerda ham, PDF da ham ko'rish mumkin.
reportlab bilan "professional" ko'rinish yasash — azob.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from ..schemas import SEVERITY_ORDER, FindingContract, Severity

TEMPLATE_DIR = Path(__file__).parent / "templates"

# Severity bo'yicha risk og'irligi. Risk score 0-100 oralig'ida kesiladi.
_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.critical: 12.0,
    Severity.high: 7.0,
    Severity.medium: 3.0,
    Severity.low: 1.0,
    Severity.info: 0.0,
}

SEVERITY_ORDER_LIST = ["critical", "high", "medium", "low", "info"]

_SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def _env() -> Environment:
    # autoescape=True MAJBURIY: nishon nomi va tool chiqishi foydalanuvchi
    # tomonidan boshqariladi. Escape bo'lmasa PDF ichiga HTML/JS inject qilinadi.
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def compute_risk_score(findings: list[FindingContract]) -> float:
    """Oddiy, tushunarli ball. CVSS vektori emas — menejment uchun ko'rsatkich."""
    total = sum(_SEVERITY_WEIGHT[f.severity] for f in findings)
    return min(100.0, round(total, 1))


def risk_grade(score: float) -> str:
    if score >= 70:
        return "KRITIK"
    if score >= 40:
        return "YUQORI"
    if score >= 15:
        return "O'RTA"
    if score > 0:
        return "PAST"
    return "TOZA"


def build_context(
    *,
    scan_id: str,
    target: str,
    tenant_name: str,
    findings: list[FindingContract],
    engines: list[dict[str, Any]],
    duration_ms: int,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    counts = dict.fromkeys(SEVERITY_ORDER_LIST, 0)
    for f in findings:
        counts[f.severity.value] += 1

    ordered = sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.title))
    score = compute_risk_score(findings)
    now = generated_at or datetime.now(UTC)

    summary_cards = [
        {
            "key": key,
            "label": _SEVERITY_LABEL[key],
            "count": counts[key],
            "pct": (counts[key] / len(ordered) * 100) if ordered else 0,
        }
        for key in SEVERITY_ORDER_LIST
    ]

    return {
        "scan_id": scan_id,
        "target": target,
        "tenant_name": tenant_name,
        "generated_at": now,
        "generated_at_str": now.strftime("%d.%m.%Y %H:%M UTC"),
        "duration_s": round(duration_ms / 1000, 1),
        "engines": engines,
        "engine_names": ", ".join(
            e["name"] for e in engines if e.get("ok") and not e.get("skipped")
        )
        or "—",
        "skipped_engines": [e for e in engines if e.get("skipped")],
        "findings": ordered,
        "summary_cards": summary_cards,
        "total_findings": len(ordered),
        "risk_score": score,
        "risk_grade": risk_grade(score),
        "counts": counts,
    }


def render_html(context: dict[str, Any]) -> str:
    return _env().get_template("report.html.j2").render(**context)


def _ensure_macos_libs() -> None:
    """macOS: Homebrew kutubxonalari dyld uchun ko'rinadigan bo'lishi kerak.

    Usiz `weasyprint` `libgobject-2.0-0` ni topolmay yiqiladi. Bu env
    o'zgaruvchisi `weasyprint` import qilinishidan OLDIN qo'yilishi kifoya.
    """
    if sys.platform != "darwin":
        return
    parts = [p for p in os.environ.get("DYLD_FALLBACK_LIBRARY_PATH", "").split(":") if p]
    for candidate in ("/opt/homebrew/lib", "/usr/local/lib"):
        if os.path.isdir(candidate) and candidate not in parts:
            parts.append(candidate)
    if parts:
        os.environ["DYLD_FALLBACK_LIBRARY_PATH"] = ":".join(parts)


def render_pdf(context: dict[str, Any]) -> bytes:
    # Import lazy — WeasyPrint og'ir va CLI uchun har doim kerak emas.
    _ensure_macos_libs()
    from weasyprint import HTML

    html = render_html(context)
    return HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf()
