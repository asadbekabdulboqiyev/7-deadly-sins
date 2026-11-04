"""Run external tools safely.

Rules:
  1. Always a timeout — a hanging tool must not kill the worker.
  2. start_new_session + killpg — child processes are killed as well.
  3. argv list — no shell injection.
  4. Missing tool — an explicit error, not a silent fail.
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
        # nuclei returns 1 in some cases (findings present), so callers check it separately
        return self.returncode == 0 and not self.timed_out


def which(tool: str) -> str | None:
    return shutil.which(tool)


_PROJECTDISCOVERY_MARKER = "projectdiscovery"


def resolve_tool(name: str, env_key: str) -> str | None:
    """Resolve a ProjectDiscovery binary, skipping shadowing copies.

    Order: `SINS_<TOOL>_BIN` override -> PATH -> well-known bin dirs. A candidate
    only counts when `<bin> -version` reports `projectdiscovery`.
    """
    override = os.environ.get(env_key, "").strip()
    if override:
        return override
    found = shutil.which(name)
    candidates: list[str] = [found] if found else []
    for directory in ("~/go/bin", "/usr/local/bin", "/opt/homebrew/bin", "~/.local/bin"):
        candidate = os.path.join(os.path.expanduser(directory), name)
        if os.path.isfile(candidate) and candidate not in candidates:
            candidates.append(candidate)
    for candidate in candidates:
        if _is_projectdiscovery(candidate):
            return candidate
    return found


def _is_projectdiscovery(path: str) -> bool:
    try:
        proc = subprocess.run(
            [path, "-version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    output = f"{proc.stdout}\n{proc.stderr}".lower()
    return proc.returncode == 0 and _PROJECTDISCOVERY_MARKER in output


def run_tool(
    argv: list[str],
    *,
    timeout: int = 900,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> RunResult:
    if not argv:
        raise ValueError("argv is empty")
    if which(argv[0]) is None:
        raise ToolNotFound(f"'{argv[0]}' not found (not on PATH)")

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
    """Kill the whole process group — child processes included."""
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
