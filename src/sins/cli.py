"""SINS CLI - attack surface and vulnerability assessment."""

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

app = typer.Typer(add_completion=False, help="SINS - attack surface and vulnerability assessment")
console = Console()


@app.command()
def adapters() -> None:
    """List the available engines."""
    table = Table(title="SINS adapters")
    table.add_column("Engine", style="bold")
    table.add_column("Sin")
    table.add_column("Category")
    table.add_column("Status")
    for name, adapter in REGISTRY.items():
        ok = adapter.available()
        table.add_row(
            name,
            adapter.sin,
            adapter.category,
            "[green]ready[/green]" if ok else "[red]not installed[/red]",
        )
    console.print(table)


@app.command("init-db")
def init_db(
    drop: bool = typer.Option(False, "--drop", help="First, delete existing tables"),
) -> None:
    """Create tables for development (Alembic for production)."""
    from .db import create_all, drop_all

    async def _run() -> None:
        if drop:
            await drop_all()
        await create_all()

    asyncio.run(_run())
    console.print("[green]Baza tayyor.[/green]")


@app.command()
def verify(target: str = typer.Argument(..., help="Domain or URL")) -> None:
    """Issue a token to prove ownership."""
    token = issue_token()
    ttl = get_settings().verify_token_ttl_hours
    console.print(
        Panel.fit(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Token:[/bold] {token}\n"
            f"[bold]Executes:[/bold] {ttl} hours\n\n"
            "[bold]1. method — DNS TXT:[/bold]\n"
            f'  _sins-verify.<domain>  TXT  "{token}"\n\n'
            "[bold]2. method — HTTP file:[/bold]\n"
            f"  /.well-known/sins-verify-{token}\n\n"
            "[dim]Keyin: sins scan <target> --verify-token " + token + "[/dim]",
            title="Authorization gate",
            border_style="yellow",
        )
    )


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain or URL"),
    engine: list[str] = typer.Option(None, "--engine", "-e", help="nuclei | osv"),
    verify_token: str | None = typer.Option(None, "--verify-token", help="Ownership token"),
    lab: bool = typer.Option(False, "--lab", help="Local/lab target (private IP only)"),
    json_out: Path | None = typer.Option(None, "--json", help="Write the result to a JSON file"),
    rate_limit: int | None = typer.Option(None, "--rate-limit", help="Requests per second"),
    templates: list[str] = typer.Option(None, "--templates", "-t", help="nuclei template path"),
    severity: list[str] = typer.Option(
        None, "--severity", "-s", help="critical|high|medium|low|info (takrorlash mumkin)"
    ),
) -> None:
    """Run the scan. Rejects it when ownership is not verified."""
    settings = get_settings()

    # --- AUTHORIZATION GATE ---
    if not lab and not verify_token:
        console.print(
            "[red]Rejected:[/red] --verify-token is required. Run `sins verify <target>` first."
        )
        raise typer.Exit(code=2)

    if lab:
        if not is_lab_target(target):
            console.print(
                "[red]Rejected:[/red] --lab is only for local/private targets. "
                f"'{target}' is an external address - use `--verify-token`."
            )
            raise typer.Exit(code=2)
    else:
        try:
            method = asyncio.run(assert_authorized(target, verify_token or ""))
        except OwnershipError as exc:
            console.print(f"[red]Rad etildi:[/red] {exc}")
            raise typer.Exit(code=3) from exc
        console.print(f"[green]Ownership verified[/green] (method: {method})")

    ctx = ScanContext(
        target=target,
        max_rps=rate_limit or settings.max_rps,
        timeout=settings.tool_timeout_seconds,
        templates=[str(Path(t).expanduser()) for t in (templates or [])],
        **({"severities": list(severity)} if severity else {}),
    )

    orchestrator = SinsOrchestrator(engine)
    if not orchestrator.adapters:
        console.print("[red]No engines are ready.[/red] Run `sins adapters` to check.")
        raise typer.Exit(code=4)

    runnable = [a for a in orchestrator.adapters if a.applies_to(target)]
    skipped = [a.name for a in orchestrator.adapters if not a.applies_to(target)]
    if not runnable:
        console.print(
            "[red]The selected engines do not apply to the target type.[/red] "
            "For the dependency audit (osv), point at a local source directory."
        )
        raise typer.Exit(code=4)

    console.print(f"[dim]Started: {', '.join(a.name for a in runnable)}[/dim]")
    if skipped:
        console.print(f"[dim]Skipped (target type not applicable): {', '.join(skipped)}[/dim]")
    with console.status("Scanning..."):
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
    scan_json: Path = typer.Argument(..., help="`sins scan --json` output"),
    out: Path = typer.Option(Path("report.pdf"), "--out", "-o", help="PDF file"),
    tenant: str = typer.Option("Client", "--tenant", help="Client name on the report"),
) -> None:
    """Generate a professional PDF report from scan JSON."""
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
        f"[green]Report ready:[/green] {out}  "
        f"({out.stat().st_size // 1024} KB, {ctx['total_findings']} findings, "
        f"risk {ctx['risk_score']}/100 — {ctx['risk_grade']})"
    )


@app.command("create-tenant")
def create_tenant(
    name: str = typer.Option(..., "--name", "-n", help="Client name (for example: Demo Bank)"),
) -> None:
    """Create a new client. The API key is shown only once."""
    from .db import get_sessionmaker
    from .services import scan_service

    async def _run() -> tuple[str, str, str]:
        async with get_sessionmaker()() as session:
            tenant, raw_key = await scan_service.create_tenant(session, name)
            return str(tenant.id), tenant.name, raw_key

    tenant_id, tenant_name, raw_key = asyncio.run(_run())
    console.print(
        Panel.fit(
            f"[bold]Client:[/bold] {tenant_name}\n"
            f"[bold]ID:[/bold] {tenant_id}\n\n"
            "[bold yellow]API key (never shown again):[/bold yellow]\n"
            f"{raw_key}\n\n"
            "[dim]Save it: only the hash is kept in the database. "
            "If lost, a new tenant is needed.[/dim]",
            title="New client created",
            border_style="green",
        )
    )


@app.command()
def prune(
    days: int = typer.Option(
        None, "--days", help="Days to keep old records (default from settings)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show only, do not delete"),
) -> None:
    """Delete old scans from the retention policy (GDPR / volume)."""
    from .db import get_sessionmaker
    from .services import scan_service

    window = days if days is not None else get_settings().retention_days

    async def _run() -> tuple[int, int]:
        async with get_sessionmaker()() as session:
            return await scan_service.prune_scans(session, older_than_days=window, dry_run=dry_run)

    scans, findings = asyncio.run(_run())
    verb = "deleted" if not dry_run else "would be deleted"
    console.print(
        f"[bold]{window}[/bold] days old: [bold]{scans}[/bold] scans, "
        f"[bold]{findings}[/bold] findings {verb}."
    )
    if dry_run:
        console.print("[dim]--dry-run: nothing was written to the database.[/dim]")


@app.command("rotate-key")
def rotate_key(
    api_key: str = typer.Option(
        ..., "--api-key", help="Current API key (for tenant identification)"
    ),
) -> None:
    """Issue a new API key for the tenant. The old key stops working immediately."""
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
        console.print("[red]API key not found.[/red]")
        raise typer.Exit(code=1)

    name, raw = result
    console.print(
        Panel.fit(
            f"[bold]Mijoz:[/bold] {name}\n\n"
            "[bold yellow]New API key (never shown again):[/bold yellow]\n"
            f"{raw}\n\n"
            "[dim]Old key is now inactive - renew the client.[/dim]",
            title="Key rotated",
            border_style="yellow",
        )
    )


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address"),
    port: int = typer.Option(8000, "--port", "-p", help="Port"),
    reload: bool = typer.Option(False, "--reload", help="Reload on code change (dev)"),
) -> None:
    """Run the HTTP API."""
    import uvicorn

    console.print(f"[green]API:[/green] http://{host}:{port}/docs")
    uvicorn.run("sins.api.main:app", host=host, port=port, reload=reload)


@app.command()
def worker() -> None:
    """Run the ARQ worker (scan jobs)."""
    from arq.worker import run_worker

    from .worker import WorkerSettings

    console.print("[green]Worker started.[/green] Press Ctrl+C to stop.")
    run_worker(WorkerSettings)


def _print_report(report: ScanReport) -> None:
    engines = Table(title="Engine natijalari")
    engines.add_column("Engine")
    engines.add_column("Sin")
    engines.add_column("Findings", justify="right")
    engines.add_column("Duration", justify="right")
    engines.add_column("Status")
    for e in report.engines:
        if e.skipped:
            engines.add_row(e.name, e.sin, "—", "—", "[dim]skipped[/dim]")
            continue
        status = "[green]ok[/green]" if e.ok else f"[red]{e.error}[/red]"
        engines.add_row(e.name, e.sin, str(e.findings), f"{e.duration_ms} ms", status)
    console.print(engines)

    if not report.findings:
        console.print("[green]No findings.[/green]")
        return

    table = Table(title=f"Findings ({len(report.findings)})")
    table.add_column("Severity")
    table.add_column("Category")
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
