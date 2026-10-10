"""MCP server exposing nuclei vulnerability scanning.

Tool:
    vuln_scan - run nuclei templates against an authorized web target

The target host is authorized first; the scan URL is then built from that
canonical host so a scheme/port in the user input can never redirect the
scan to an unauthorized host.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from recon.core.allowlist import assert_authorized
from recon.core.parsers import parse_nuclei_jsonl
from recon.core.runner import run_command
from recon.servers._common import envelope, guarded

mcp = MCPServer("nuclei-recon")

_VULN_SCAN_TIMEOUT_S = 600.0
_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


@mcp.tool()
@guarded
def vuln_scan(
    target: str,
    port: int | None = None,
    scheme: str = "http",
    severity: str | None = None,
) -> dict:
    """Scan an authorized web target with nuclei templates.

    Args:
        target: Host to scan. Must be on the allowlist.
        port: Optional port to append to the URL (e.g. 3000 for Juice Shop).
        scheme: "http" or "https".
        severity: Optional comma-separated filter, e.g. "medium,high,critical".
            Only the known nuclei severities are passed through.

    Returns:
        An envelope whose ``result`` is a findings list sorted most-severe
        first. An unauthorized target returns an ``authorized=False`` envelope.

    Raises:
        ValueError: if scheme, severity, or port is invalid.
    """
    host = assert_authorized(target)

    if scheme not in ("http", "https"):
        raise ValueError("scheme must be 'http' or 'https'")

    url = f"{scheme}://{host}"
    if port is not None:
        if not 1 <= port <= 65535:
            raise ValueError("port out of range")
        url = f"{url}:{port}"

    command = ["nuclei", "-u", url, "-jsonl", "-silent", "-disable-update-check"]

    if severity:
        requested = [s.strip().lower() for s in severity.split(",") if s.strip()]
        bad = [s for s in requested if s not in _VALID_SEVERITIES]
        if bad:
            raise ValueError(f"unknown severity values: {', '.join(bad)}")
        command += ["-severity", ",".join(requested)]

    result = run_command(command, timeout=_VULN_SCAN_TIMEOUT_S)
    findings = parse_nuclei_jsonl(result.stdout)
    payload = {"url": url, "findings": findings, "finding_count": len(findings)}
    return envelope("nuclei", host, payload, command=result)


if __name__ == "__main__":
    mcp.run()
