"""MCP server that orchestrates the other recon servers over MCP.

Unlike the leaf servers, this one is also an MCP *client*: each workflow
spawns the nmap / nuclei / osint servers as subprocesses and calls their
tools over stdio (see ``recon.orchestration.client``). So the servers really
do communicate with one another — the orchestrator is a client of three
servers, and a server to whatever client (Claude, Inspector) drives it.

Tools:
    quick_recon     - fast triage: open ports + DNS records
    full_assessment - port scan -> service detection on open ports ->
                      vuln scan -> passive OSINT

The orchestrator authorizes the target once up front (a fast, clear refusal
before any subprocess is spawned); each leaf server then re-authorizes as
defense in depth. Every step is isolated: a failed or refused step is
recorded and the workflow keeps going.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from mcp.server.mcpserver import MCPServer

from recon.core.allowlist import TargetNotAuthorized, assert_authorized
from recon.orchestration.client import call_remote_tool

mcp = MCPServer("recon-orchestrator")

# Ports that, if open, are worth pointing a web vuln scan at (best first).
_WEB_PORTS = (3000, 80, 8080, 8000, 443, 8443)


async def _step(name: str, call: Callable[[], Awaitable[dict]]) -> dict:
    """Run one workflow step, capturing transport errors instead of raising.

    ``ok`` is True only when the remote call came back with a usable,
    authorized result. A refusal or tool error from the leaf server is
    reported in-band (``ok=False`` with the envelope attached) so one gap
    does not sink the whole assessment.
    """
    try:
        data = await call()
    except Exception as exc:  # noqa: BLE001 - report transport failures, don't crash
        return {"step": name, "ok": False, "error": f"{exc.__class__.__name__}: {exc}", "data": None}

    ok = data.get("error") is None and data.get("authorized", True)
    return {"step": name, "ok": ok, "data": data}


def _open_ports(port_scan_step: dict) -> list[int]:
    """Pull open TCP port numbers out of a port_scan step result."""
    data = port_scan_step.get("data") or {}
    result = data.get("result") or {}
    return [p["port"] for p in result.get("open_ports", [])]


def _refusal(workflow: str, target: str, exc: TargetNotAuthorized) -> dict:
    return {
        "workflow": workflow,
        "target": target,
        "authorized": False,
        "error": str(exc),
        "steps": [],
        "summary": {},
    }


@mcp.tool()
async def quick_recon(target: str) -> dict:
    """Fast triage of an authorized target: open ports plus DNS records.

    An unauthorized target returns an ``authorized=False`` result without
    spawning any scanner.
    """
    try:
        host = assert_authorized(target)
    except TargetNotAuthorized as exc:
        return _refusal("quick_recon", target, exc)

    steps = [
        await _step(
            "port_scan",
            lambda: call_remote_tool("nmap", "port_scan", {"target": host, "ports": "1-1000"}),
        ),
        await _step(
            "dns_records",
            lambda: call_remote_tool("osint", "dns_records", {"domain": host}),
        ),
    ]
    return {
        "workflow": "quick_recon",
        "target": host,
        "authorized": True,
        "error": None,
        "steps": steps,
        "summary": {"open_ports": _open_ports(steps[0])},
    }


@mcp.tool()
async def full_assessment(target: str, scheme: str = "http") -> dict:
    """Full chained assessment of an authorized target.

    Runs a port scan, then version detection against whatever ports are open,
    a nuclei vuln scan against the most likely web port, and passive OSINT
    (subdomains, DNS, WHOIS) — each as an MCP call to the relevant leaf
    server. An unauthorized target returns an ``authorized=False`` result
    without spawning any scanner.
    """
    try:
        host = assert_authorized(target)
    except TargetNotAuthorized as exc:
        return _refusal("full_assessment", target, exc)

    ps = await _step(
        "port_scan",
        lambda: call_remote_tool("nmap", "port_scan", {"target": host, "ports": "1-1000"}),
    )
    open_ports = _open_ports(ps)
    steps = [ps]

    if open_ports:
        spec = ",".join(str(p) for p in sorted(open_ports))
        steps.append(
            await _step(
                "service_detect",
                lambda: call_remote_tool("nmap", "service_detect", {"target": host, "ports": spec}),
            )
        )

    web_port = next((p for p in _WEB_PORTS if p in open_ports), None)
    vuln_args: dict[str, Any] = {"target": host, "scheme": scheme}
    if web_port is not None:
        vuln_args["port"] = web_port
    steps.append(
        await _step("vuln_scan", lambda: call_remote_tool("nuclei", "vuln_scan", vuln_args))
    )

    steps.append(
        await _step(
            "find_subdomains",
            lambda: call_remote_tool("osint", "find_subdomains", {"domain": host}),
        )
    )
    steps.append(
        await _step(
            "dns_records",
            lambda: call_remote_tool("osint", "dns_records", {"domain": host}),
        )
    )
    steps.append(
        await _step(
            "whois_lookup",
            lambda: call_remote_tool("osint", "whois_lookup", {"domain": host}),
        )
    )

    return {
        "workflow": "full_assessment",
        "target": host,
        "authorized": True,
        "error": None,
        "steps": steps,
        "summary": {
            "open_ports": open_ports,
            "web_port_scanned": web_port,
            "steps_ok": sum(1 for s in steps if s["ok"]),
            "steps_failed": sum(1 for s in steps if not s["ok"]),
        },
    }


if __name__ == "__main__":
    mcp.run()
