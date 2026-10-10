"""A small, safe wrapper around subprocess for running recon CLIs.

Design choices that matter for a security tool:

* Commands are passed as an argument **list**, never a shell string, so there
  is no shell to inject into.
* Every run has a mandatory timeout; a process that overruns is killed and
  reported as ``timed_out`` rather than hanging the MCP server.
* A missing binary (tool not installed) is reported as a clean result, not an
  uncaught exception, so the agent gets an actionable message.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass

__all__ = ["CommandResult", "ToolNotInstalled", "run_command"]

DEFAULT_TIMEOUT_S = 120.0


class ToolNotInstalled(Exception):
    """Raised when the requested CLI binary is not on PATH."""


@dataclass(frozen=True)
class CommandResult:
    """The outcome of a single command run."""

    command: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool

    @property
    def ok(self) -> bool:
        """True if the process finished on its own with exit code 0."""
        return self.returncode == 0 and not self.timed_out

    def as_dict(self) -> dict:
        return {
            "command": list(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_s": round(self.duration_s, 3),
            "timed_out": self.timed_out,
            "ok": self.ok,
        }


def run_command(
    command: list[str],
    timeout: float = DEFAULT_TIMEOUT_S,
    check_binary: bool = True,
) -> CommandResult:
    """Run *command* with a hard timeout and capture its output.

    Args:
        command: Program and arguments as a list. Never a shell string.
        timeout: Seconds before the process is killed and marked timed out.
        check_binary: If True, verify the binary exists on PATH first and
            raise :class:`ToolNotInstalled` with a clear message if not.

    Returns:
        A :class:`CommandResult`. A non-zero exit code is returned normally
        (``ok`` is False); it is not raised, because recon tools routinely
        exit non-zero when they find nothing.
    """
    if not command:
        raise ValueError("command must not be empty")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    if check_binary and shutil.which(command[0]) is None:
        raise ToolNotInstalled(
            f"{command[0]!r} is not installed or not on PATH. "
            f"Install it (see docker-compose.yml for the lab image) and retry."
        )

    start = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        duration = time.monotonic() - start
        return CommandResult(
            command=tuple(command),
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration_s=duration,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - start
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return CommandResult(
            command=tuple(command),
            returncode=None,
            stdout=stdout,
            stderr=stderr + f"\n[timed out after {timeout}s]",
            duration_s=duration,
            timed_out=True,
        )
