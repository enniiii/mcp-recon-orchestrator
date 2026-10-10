"""MCP server exposing nmap port scanning and service detection.

Tools:
    port_scan     - which TCP ports are open on an authorized host
    service_detect - what services/versions are running on those ports

Both authorize the target first and run nmap with XML output, which the
parser turns into a clean dict.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from recon.core.allowlist import assert_authorized
from recon.core.parsers import parse_nmap_xml
from recon.core.runner import run_command
from recon.servers._common import envelope, guarded

mcp = MCPServer("nmap-recon")

# nmap can take a while on wide ranges; give service detection extra room.
_PORT_SCAN_TIMEOUT_S = 180.0
_SERVICE_DETECT_TIMEOUT_S = 300.0


def _nmap(host: str, extra_args: list[str], timeout: float) -> dict:
    """Run nmap against an already-authorized host and parse the XML."""
    command = ["nmap", "-Pn", "-T4", *extra_args, "-oX", "-", host]
    result = run_command(command, timeout=timeout)
    if result.stdout.strip():
        parsed = parse_nmap_xml(result.stdout)
    else:
        parsed = {"hosts": [], "open_ports": [], "open_port_count": 0}
    return envelope("nmap", host, parsed, command=result)


@mcp.tool()
@guarded
def port_scan(target: str, ports: str = "1-1000") -> dict:
    """Scan TCP ports on an authorized target.

    Args:
        target: Host to scan. Must be on the allowlist (localhost, your
            Docker lab, or your DuckDNS subdomain).
        ports: nmap port spec, e.g. "1-1000", "22,80,443", or "-" for all.

    Returns:
        An envelope whose ``result`` lists open ports with basic service
        names. If the target is not on the allowlist, the envelope has
        ``authorized=False`` and an ``error`` explaining the refusal.
    """
    host = assert_authorized(target)
    return _nmap(host, ["-p", ports], _PORT_SCAN_TIMEOUT_S)


@mcp.tool()
@guarded
def service_detect(target: str, ports: str = "1-1000") -> dict:
    """Detect service products and versions on an authorized target.

    Runs nmap with version detection (``-sV``). Slower than a plain port
    scan, so prefer passing a narrow ``ports`` spec. An unauthorized target
    returns an ``authorized=False`` envelope rather than scanning.
    """
    host = assert_authorized(target)
    return _nmap(host, ["-sV", "-p", ports], _SERVICE_DETECT_TIMEOUT_S)


if __name__ == "__main__":
    mcp.run()
