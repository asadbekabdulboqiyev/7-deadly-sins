"""SINS CLI — dashboard yozishdan oldin hamma narsa shu yerda ishlaydi."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .adapters import REGISTRY, ScanContext
from .authz import OwnershipError, assert_authorized, issue_token
from .config import get_settings
from .orchestrator import ScanReport, SinsOrchestrator

app = typer.Typer(add_completion=False, help="SINS — attack surface & vulnerability assessment")
console = Console()


def _is_lab_target(target: str) -> bool:
    """Faqat lokal/lab nishonlar uchun egalik tekshiruvisiz ruxsat."""
    host = target
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix) :]
    host = host.split("/")[0].split(":")[0].lower()

    if host in {"localhost", "::1"} or host.endswith((".local", ".test", ".localhost")):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


@app.command()
def adapters() -> None:
    """Mavjud engine'larni ko'rsatadi."""
    table = Table(title="SINS adapters")
    table.add_column("Engine", style="bold")
    table.add_column("Sin")
    table.add_column("Kategoriya")
    table.add_column("Holat")
    for name, adapter in REGISTRY.items():
        ok = adapter.available()
        table.add_row(
            name,
            adapter.sin,
            adapter.category,
            "[green]tayyor[/green]" if ok else "[red]o'rnatilmagan[/red]",
        )
    console.print(table)


@app.command("init-db")
def init_db(
    drop: bool = typer.Option(False, "--drop", help="Avval mavjud jadvallarni o'chirish"),
) -> None:
    """Dev uchun jadvallarni yaratadi (production'da Alembic)."""
    from .db import create_all, drop_all

    async def _run() -> None:
        if drop:
            await drop_all()
        await create_all()

    asyncio.run(_run())
    console.print("[green]Baza tayyor.[/green]")


@app.command()
def verify(target: str = typer.Argument(..., help="Domen yoki URL")) -> None:
    """Egalikni isbotlash uchun token yaratadi va ko'rsatma beradi."""
    token = issue_token()
    ttl = get_settings().verify_token_ttl_hours
    console.print(
        Panel.fit(
            f"[bold]Nishon:[/bold] {target}\n"
            f"[bold]Token:[/bold] {token}\n"
            f"[bold]Amal qiladi:[/bold] {ttl} soat\n\n"
            "[bold]1-usul — DNS TXT:[/bold]\n"
            f"  _sins-verify.<domain>  TXT  \"{token}\"\n\n"
            "[bold]2-usul — HTTP fayl:[/bold]\n"
            f"  /.well-known/sins-verify-{token}\n\n"
            "[dim]Keyin: sins scan <target> --verify-token " + token + "[/dim]",
            title="Authorization gate",
            border_style="yellow",
        )
    )


@app.command()
def scan(
    target: str = typer.Argument(..., help="Nishon (domen, URL yoki lokal manzil)"),
    engine: list[str] = typer.Option(None, "--engine", "-e", help="nuclei | osv"),
    verify_token: str | None = typer.Option(None, "--verify-token", help="Egalik tokeni"),
    lab: bool = typer.Option(False, "--lab", help="Lokal/lab nishon (faqat private IP)"),
    json_out: Path | None = typer.Option(None, "--json", help="Natijani JSON ga yozish"),
    rate_limit: int | None = typer.Option(None, "--rate-limit", help="So'rov/sekund"),
    templates: list[str] = typer.Option(None, "--templates", "-t", help="nuclei template yo'li"),
    severity: list[str] = typer.Option(
        None, "--severity", "-s", help="critical|high|medium|low|info (takrorlash mumkin)"
    ),
) -> None:
    """Skan boshlaydi. Egalik isbotlanmasa — bloklanadi."""
    settings = get_settings()

    # --- AUTHORIZATION GATE ---
    if not lab and not verify_token:
        console.print(
            "[red]Rad etildi:[/red] --verify-token kerak. "
            "Avval `sins verify <target>` ni ishlating."
        )
        raise typer.Exit(code=2)

    if lab:
        if not _is_lab_target(target):
            console.print(
                f"[red]Rad etildi:[/red] --lab faqat lokal/private nishonlar uchun. "
                f"'{target}' tashqi manzil — `--verify-token` ishlating."
            )
            raise typer.Exit(code=2)
    else:
        try:
            method = asyncio.run(assert_authorized(target, verify_token or ""))
        except OwnershipError as exc:
            console.print(f"[red]Rad etildi:[/red] {exc}")
            raise typer.Exit(code=3) from exc
        console.print(f"[green]Egalik tasdiqlandi[/green] (usul: {method})")

    ctx = ScanContext(
        target=target,
        max_rps=rate_limit or settings.max_rps,
        timeout=settings.tool_timeout_seconds,
        templates=[str(Path(t).expanduser()) for t in (templates or [])],
        **({"severities": list(severity)} if severity else {}),
    )

    orchestrator = SinsOrchestrator(engine)
    if not orchestrator.adapters:
        console.print("[red]Hech qanday engine tayyor emas.[/red] `sins adapters` ni tekshiring.")
        raise typer.Exit(code=4)

    console.print(f"[dim]Ishga tushdi: {', '.join(a.name for a in orchestrator.adapters)}[/dim]")
    with console.status("Skanlanmoqda..."):
        report = asyncio.run(orchestrator.run(ctx))

    _print_report(report)

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "target": report.target,
            "duration_ms": report.duration_ms,
            "engines": [
                {
                    "name": e.name,
                    "sin": e.sin,
                    "ok": e.ok,
                    "findings": e.findings,
                    "duration_ms": e.duration_ms,
                    "error": e.error,
                }
                for e in report.engines
            ],
            "findings": [f.model_dump(mode="json") for f in report.findings],
        }
        json_out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"[green]Saqlandi:[/green] {json_out}")

    has_findings = bool(report.findings)
    sys.exit(0 if not has_findings else 0)


def _print_report(report: ScanReport) -> None:
    engines = Table(title="Engine natijalari")
    engines.add_column("Engine")
    engines.add_column("Sin")
    engines.add_column("Topilma", justify="right")
    engines.add_column("Vaqt", justify="right")
    engines.add_column("Holat")
    for e in report.engines:
        status = "[green]ok[/green]" if e.ok else f"[red]{e.error}[/red]"
        engines.add_row(e.name, e.sin, str(e.findings), f"{e.duration_ms} ms", status)
    console.print(engines)

    if not report.findings:
        console.print("[green]Topilma yo'q.[/green]")
        return

    table = Table(title=f"Topilmalar ({len(report.findings)})")
    table.add_column("Severity")
    table.add_column("Kategoriya")
    table.add_column("Sarlavha", max_width=50)
    table.add_column("Joylashuv", max_width=40)
    table.add_column("Manba")
    colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }
    for f in report.findings:
        table.add_row(
            f"[{colors[f.severity]}]{f.severity}[/]",
            f.category,
            f.title,
            f.location,
            ",".join(f.source_tools),
        )
    console.print(table)


if __name__ == "__main__":
    app()
