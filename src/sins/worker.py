"""ARQ worker — scan jobs and scheduled cleanup.

Run with: `arq sins.worker.WorkerSettings` (or `sins worker`).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, ClassVar

from arq import cron
from arq.connections import RedisSettings

from .config import get_settings
from .db import get_sessionmaker
from .observability import METRICS, configure_logging
from .services import scan_service

log = logging.getLogger(__name__)


async def run_scan(ctx: dict[str, Any], scan_id: str) -> str:
    """ARQ job: runs the scan and persists its state to the DB."""
    log.info("run_scan started", extra={"event": "job.start", "scan_id": scan_id})
    try:
        parsed = uuid.UUID(scan_id)
    except ValueError:
        log.error("run_scan: invalid scan_id %r", scan_id)
        return "invalid_id"

    await scan_service.execute_scan(parsed)
    log.info("run_scan finished", extra={"event": "job.done", "scan_id": scan_id})
    return "done"


async def prune_old_scans(ctx: dict[str, Any]) -> str:
    """Daily cron: deletes scans older than the retention policy."""
    days = get_settings().retention_days
    async with get_sessionmaker()() as session:
        scans, findings = await scan_service.prune_scans(
            session, older_than_days=days, dry_run=False
        )
    log.info(
        "cron prune finished",
        extra={"event": "cron.prune", "scans": scans, "findings": findings, "days": days},
    )
    return f"pruned scans={scans} findings={findings}"


async def refresh_metrics(ctx: dict[str, Any]) -> None:
    """Refreshes queue and scan-state gauges every minute."""
    from sqlalchemy import func, select

    from .models import Scan, ScanStatus

    async with get_sessionmaker()() as session:
        rows = await session.execute(select(Scan.status, func.count()).group_by(Scan.status))
        counts = {str(status): int(count) for status, count in rows}

    for status in ScanStatus:
        METRICS.gauge("sins_scans", float(counts.get(str(status), 0)), {"status": str(status)})


async def startup(ctx: dict[str, Any]) -> None:
    configure_logging()
    METRICS.inc("sins_worker_starts_total")
    log.info("worker started", extra={"event": "worker.start"})


async def shutdown(ctx: dict[str, Any]) -> None:
    from .db import get_engine

    await get_engine().dispose()
    log.info("worker stopped", extra={"event": "worker.stop"})


class WorkerSettings:
    functions: ClassVar[list] = [run_scan]
    cron_jobs: ClassVar[list] = [
        cron(prune_old_scans, hour=3, minute=30, run_at_startup=False),
        cron(refresh_metrics, minute=set(range(0, 60, 5)), second=0),
    ]
    on_startup = startup
    on_shutdown = shutdown
    # Scans are heavy and depend on external tools — 2 concurrent jobs is enough.
    max_jobs = 2
    job_timeout = 1800
    keep_result = 3600
    # If a job fails twice it is not retried: external tool failures
    # usually are not fixed by retrying and only tie up the queue.
    max_tries = 2
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
