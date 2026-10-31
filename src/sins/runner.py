"""Tashqi tool'larni xavfsiz ishga tushirish.

Qoidalar:
  1. Har doim timeout — osilib qolgan tool workerni o'ldirmasin.
  2. start_new_session + killpg — bolalar jarayonlar ham o'ldiriladi.
  3. argv list — shell injection yo'q.
  4. Tool topilmasa — aniq xato, jim fail emas.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field


class ToolNotFound(RuntimeError):
    pass


@dataclass(slots=True)
class RunResult:
    argv: list[str] = field(default_factory=list)
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        # nuclei ba'zi holatlarda 1 qaytaradi (topilma bor), shuning uchun alohida tekshiriladi
        return self.returncode == 0 and not self.timed_out


def which(tool: str) -> str | None:
    return shutil.which(tool)


def run_tool(
    argv: list[str],
    *,
    timeout: int = 900,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> RunResult:
    if not argv:
        raise ValueError("argv bo'sh")
    if which(argv[0]) is None:
        raise ToolNotFound(f"'{argv[0]}' topilmadi (PATH da yo'q)")

    full_env = {**os.environ, **(env or {})}
    started = time.monotonic()

    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        start_new_session=True,
        cwd=cwd,
        env=full_env,
    )

    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        stdout, stderr = proc.communicate()

    return RunResult(
        argv=argv,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout or "",
        stderr=stderr or "",
        timed_out=timed_out,
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def _kill_tree(proc: subprocess.Popen) -> None:
    """Butun process guruhini o'ldiradi — farzand jarayonlar ham."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    with contextlib.suppress(ProcessLookupError):
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
