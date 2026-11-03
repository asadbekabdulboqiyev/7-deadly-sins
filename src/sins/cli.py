"""SINS CLI — dashboard yozishdan oldin hamma narsa shu yerda ishlaydi."""

from __future__ import annotations

import asyncio
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
from .targets import is_lab_target

app = typer.Typer(add_completion=False, help="SINS — attack surface & vulnerability assessment")
console = Console()


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
            f'  _sins-verify.<domain>  TXT  "{token}"\n\n'
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
        if not is_lab_target(target):
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

    runnable = [a for a in orchestrator.adapters if a.applies_to(target)]
    skipped = [a.name for a in orchestrator.adapters if not a.applies_to(target)]
    if not runnable:
        console.print(
            f"[red]Tanlangan engine'lar '{target}' nishon turiga mos emas.[/red] "
            "Dependency auditi (osv) uchun lokal papka bering."
        )
        raise typer.Exit(code=4)

    console.print(f"[dim]Ishga tushdi: {', '.join(a.name for a in runnable)}[/dim]")
    if skipped:
        console.print(f"[dim]O'tkazib yuborildi (nishon turi mos emas): {', '.join(skipped)}[/dim]")
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
                    "attempts": e.attempts,
                    "skipped": e.skipped,
                    "skip_reason": e.skip_reason,
                }
                for e in report.engines
            ],
            "findings": [f.model_dump(mode="json") for f in report.findings],
        }
        json_out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"[green]Saqlandi:[/green] {json_out}")

    has_findings = bool(report.findings)
    sys.exit(0 if not has_findings else 0)


@app.command()
def report(
    scan_json: Path = typer.Argument(..., help="`sins scan --json` chiqishi"),
    out: Path = typer.Option(Path("report.pdf"), "--out", "-o", help="PDF fayl"),
    tenant: str = typer.Option("Mijoz", "--tenant", help="Hisobotdagi mijoz nomi"),
) -> None:
    """Skan JSON'idan professional PDF hisobot yasaydi."""
    from .report import build_context, render_pdf
    from .schemas import FindingContract

    payload = json.loads(scan_json.read_text(encoding="utf-8"))
    findings = [FindingContract(**f) for f in payload.get("findings", [])]

    ctx = build_context(
        scan_id=payload.get("scan_id", scan_json.stem),
        target=payload.get("target", "—"),
        tenant_name=tenant,
        findings=findings,
        engines=payload.get("engines", []),
        duration_ms=payload.get("duration_ms", 0),
    )

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(render_pdf(ctx))
    console.print(
        f"[green]Hisobot tayyor:[/green] {out}  "
        f"({out.stat().st_size // 1024} KB, {ctx['total_findings']} topilma, "
        f"risk {ctx['risk_score']}/100 — {ctx['risk_grade']})"
    )


@app.command("create-tenant")
def create_tenant(
    name: str = typer.Option(..., "--name", "-n", help="Mijoz nomi (masalan: Demo Bank)"),
) -> None:
    """Yangi mijoz yaratadi. API kalit faqat BIR MARTA ko'rsatiladi."""
    from .db import get_sessionmaker
    from .services import scan_service

    async def _run() -> tuple[str, str, str]:
        async with get_sessionmaker()() as session:
            tenant, raw_key = await scan_service.create_tenant(session, name)
            return str(tenant.id), tenant.name, raw_key

    tenant_id, tenant_name, raw_key = asyncio.run(_run())
    console.print(
        Panel.fit(
            f"[bold]Mijoz:[/bold] {tenant_name}\n"
            f"[bold]ID:[/bold] {tenant_id}\n\n"
            f"[bold yellow]API kalit (boshqa ko'rsatilmaydi):[/bold yellow]\n"
            f"{raw_key}\n\n"
            "[dim]Saqlang: bazada faqat hash qoladi. Yo'qolsa — yangi tenant kerak.[/dim]",
            title="Yangi mijoz yaratildi",
            border_style="green",
        )
    )


@app.command()
def prune(
    days: int = typer.Option(None, "--days", help="Necha kundan eski yozuvlar (sukut: sozlamadan)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Faqat ko'rsatadi, o'chirmaydi"),
) -> None:
    """Saqlash siyosatidan eski skanlarni o'chiradi (GDPR/hajm uchun)."""
    from .db import get_sessionmaker
    from .services import scan_service

    window = days if days is not None else get_settings().retention_days

    async def _run() -> tuple[int, int]:
        async with get_sessionmaker()() as session:
            return await scan_service.prune_scans(session, older_than_days=window, dry_run=dry_run)

    scans, findings = asyncio.run(_run())
    verb = "o'chiriladi" if not dry_run else "o'chirilgan bo'lardi"
    console.print(
        f"[bold]{window}[/bold] kundan eski: [bold]{scans}[/bold] skan, "
        f"[bold]{findings}[/bold] topilma {verb}."
    )
    if dry_run:
        console.print("[dim]--dry-run: bazaga hech narsa yozilmadi.[/dim]")


@app.command("rotate-key")
def rotate_key(
    api_key: str = typer.Option(..., "--api-key", help="Joriy API kalit (tenantni aniqlash uchun)"),
) -> None:
    """Tenant uchun yangi API kalit beradi. Eski kalit darhol ishlamaydi."""
    from .db import get_sessionmaker
    from .services import scan_service

    async def _run() -> tuple[str, str] | None:
        async with get_sessionmaker()() as session:
            tenant = await scan_service.get_tenant_by_key(session, api_key)
            if tenant is None:
                return None
            raw = await scan_service.rotate_api_key(session, tenant)
            return tenant.name, raw

    result = asyncio.run(_run())
    if result is None:
        console.print("[red]Kalit topilmadi.[/red]")
        raise typer.Exit(code=1)

    name, raw = result
    console.print(
        Panel.fit(
            f"[bold]Mijoz:[/bold] {name}\n\n"
            f"[bold yellow]Yangi API kalit (boshqa ko'rsatilmaydi):[/bold yellow]\n"
            f"{raw}\n\n"
            "[dim]Eski kalit shu zahoti ishlamaydi — mijozni yangilang.[/dim]",
            title="Kalit almashtirildi",
            border_style="yellow",
        )
    )


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind manzil"),
    port: int = typer.Option(8000, "--port", "-p", help="Port"),
    reload: bool = typer.Option(False, "--reload", help="Kod o'zgarsa qayta yuklash (dev)"),
) -> None:
    """HTTP API'ni ishga tushiradi."""
    import uvicorn

    console.print(f"[green]API:[/green] http://{host}:{port}/docs")
    uvicorn.run("sins.api.main:app", host=host, port=port, reload=reload)


@app.command()
def worker() -> None:
    """ARQ worker'ni ishga tushiradi (skan job'lari)."""
    from arq.worker import run_worker

    from .worker import WorkerSettings

    console.print("[green]Worker ishga tushdi.[/green] Ctrl+C — to'xtatish.")
    run_worker(WorkerSettings)


def _print_report(report: ScanReport) -> None:
    engines = Table(title="Engine natijalari")
    engines.add_column("Engine")
    engines.add_column("Sin")
    engines.add_column("Topilma", justify="right")
    engines.add_column("Vaqt", justify="right")
    engines.add_column("Holat")
    for e in report.engines:
        if e.skipped:
            engines.add_row(e.name, e.sin, "—", "—", "[dim]o'tkazib yuborildi[/dim]")
            continue
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
