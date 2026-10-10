"""Client-side orchestration: driving the leaf MCP servers over stdio.

The orchestrator server is itself an MCP *client* of the nmap, nuclei, and
osint servers. This package holds the thin client helper it uses to spawn a
server as a subprocess, speak MCP to it, and call a tool.
"""

from recon.orchestration.client import (
    SERVER_MODULES,
    call_remote_tool,
    list_remote_tools,
)

__all__ = ["SERVER_MODULES", "call_remote_tool", "list_remote_tools"]
