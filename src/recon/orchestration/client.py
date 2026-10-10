"""A minimal MCP client for talking to the leaf recon servers over stdio.

Each call spawns the target server as a subprocess, performs the MCP
handshake, calls one tool, and tears the subprocess down. Recon operations
are slow enough that per-call spawn overhead is irrelevant, and a fresh
process per call keeps the servers fully isolated from one another.

The child process inherits this process's environment — crucially the
``RECON_ALLOWED_*`` allowlist variables and ``PATH`` — plus a ``PYTHONPATH``
that guarantees ``recon`` is importable even from a non-installed checkout.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import recon
from mcp import Client, StdioServerParameters

__all__ = ["SERVER_MODULES", "call_remote_tool", "list_remote_tools"]

# Logical server name -> importable module that runs it over stdio.
SERVER_MODULES: dict[str, str] = {
    "nmap": "recon.servers.nmap_server",
    "nuclei": "recon.servers.nuclei_server",
    "osint": "recon.servers.osint_server",
}

# Directory containing the ``recon`` package (the src/ root).
_SRC_ROOT = str(Path(recon.__file__).resolve().parents[1])


def _child_params(module: str) -> StdioServerParameters:
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        _SRC_ROOT + os.pathsep + existing if existing else _SRC_ROOT
    )
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", module],
        env=env,
    )


def _resolve_module(server: str) -> str:
    try:
        return SERVER_MODULES[server]
    except KeyError:
        raise ValueError(
            f"unknown server {server!r}; expected one of {sorted(SERVER_MODULES)}"
        ) from None


def _unwrap(result: Any) -> dict:
    """Turn a CallToolResult into the plain dict our tools return.

    Prefers the structured content; falls back to JSON-parsing the first text
    block. A server-side error that was *not* already converted into a
    structured envelope (i.e. an unexpected crash) is surfaced as an error
    dict so the orchestrator can record it instead of raising.
    """
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        return structured

    text = ""
    for block in getattr(result, "content", []) or []:
        if getattr(block, "text", None):
            text = block.text
            break

    if getattr(result, "is_error", False):
        return {"result": None, "error": text or "remote tool error"}

    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {"result": text, "error": None}


async def call_remote_tool(
    server: str, tool: str, arguments: dict | None = None
) -> dict:
    """Call ``tool`` on the named leaf server over MCP and return its dict."""
    module = _resolve_module(server)
    async with Client(_child_params(module)) as client:
        result = await client.call_tool(tool, arguments or {})
    return _unwrap(result)


async def list_remote_tools(server: str) -> list[str]:
    """Return the tool names advertised by the named leaf server."""
    module = _resolve_module(server)
    async with Client(_child_params(module)) as client:
        listing = await client.list_tools()
    return [t.name for t in listing.tools]
