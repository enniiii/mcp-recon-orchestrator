"""Helpers shared by the MCP server modules.

The envelope gives every tool a predictable JSON shape. ``guarded`` turns the
two *expected* failures — an unauthorized target and a missing scanner — into
that same structured shape instead of an opaque protocol error, so a refusal
is readable both in the MCP Inspector and by the orchestrator over the wire.
"""

from __future__ import annotations

import functools
from typing import Any, Callable

from recon.core.allowlist import TargetNotAuthorized
from recon.core.runner import CommandResult, ToolNotInstalled


def envelope(
    tool: str,
    target: str,
    result: Any,
    command: CommandResult | list[str] | None = None,
    *,
    authorized: bool = True,
    error: str | None = None,
) -> dict:
    """Wrap a tool result in a consistent structure.

    ``target`` is the canonical, authorized host on success — never the raw
    user-supplied string — so logs and output reflect exactly what was acted
    on.
    """
    cmd: list[str] | None
    meta: dict[str, Any] = {}
    if isinstance(command, CommandResult):
        cmd = list(command.command)
        meta = {
            "returncode": command.returncode,
            "duration_s": round(command.duration_s, 3),
            "timed_out": command.timed_out,
        }
    else:
        cmd = command

    return {
        "tool": tool,
        "target": target,
        "authorized": authorized,
        "command": cmd,
        "meta": meta,
        "result": result,
        "error": error,
    }


def _target_of(args: tuple, kwargs: dict) -> str | None:
    """Best-effort recovery of the target string for an error envelope."""
    for key in ("target", "domain"):
        if key in kwargs:
            return kwargs[key]
    return args[0] if args else None


def guarded(fn: Callable[..., dict]) -> Callable[..., dict]:
    """Convert expected tool failures into structured error envelopes.

    * :class:`TargetNotAuthorized` -> ``authorized=False`` refusal.
    * :class:`ToolNotInstalled` -> authorized, but ``error`` explains the gap.

    Any other exception is left to propagate; those are real bugs and should
    surface as errors, not be silently swallowed. ``functools.wraps`` keeps the
    original signature so the MCP schema is still generated correctly.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> dict:
        target = _target_of(args, kwargs)
        try:
            return fn(*args, **kwargs)
        except TargetNotAuthorized as exc:
            return envelope(
                fn.__name__, target, None, authorized=False, error=str(exc)
            )
        except ToolNotInstalled as exc:
            return envelope(fn.__name__, target, None, error=str(exc))

    return wrapper
