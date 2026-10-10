"""Real MCP client <-> server round trips over stdio.

These spawn a leaf server as a subprocess and speak MCP to it, exactly as the
orchestrator does. They need only Python (no nmap/nuclei), so they prove the
inter-server communication path works without depending on the scanners.
"""

import asyncio

import pytest

from recon.orchestration.client import (
    SERVER_MODULES,
    call_remote_tool,
    list_remote_tools,
)


def test_list_remote_tools_round_trip():
    names = asyncio.run(list_remote_tools("nmap"))
    assert set(names) == {"port_scan", "service_detect"}


def test_all_servers_advertise_their_tools():
    expected = {
        "nmap": {"port_scan", "service_detect"},
        "nuclei": {"vuln_scan"},
        "osint": {"find_subdomains", "dns_records", "whois_lookup"},
    }
    for server, tools in expected.items():
        assert server in SERVER_MODULES
        assert set(asyncio.run(list_remote_tools(server))) == tools


def test_call_remote_tool_refuses_unauthorized_over_the_wire():
    # The refusal is produced by the child server and travels back as data.
    out = asyncio.run(
        call_remote_tool("nmap", "port_scan", {"target": "example.com", "ports": "80"})
    )
    assert out["authorized"] is False
    assert out["result"] is None
    assert "allowlist" in out["error"].lower()


def test_call_remote_tool_authorized_but_tool_missing():
    # localhost is authorized; nmap almost certainly is not installed in CI,
    # so we expect an authorized envelope carrying a "not installed" error.
    # If nmap *is* present, the scan simply succeeds — both are valid.
    out = asyncio.run(
        call_remote_tool("nmap", "port_scan", {"target": "localhost", "ports": "80"})
    )
    assert out["authorized"] is True
    if out["error"] is not None:
        assert "not installed" in out["error"].lower()
    else:
        assert "open_ports" in out["result"]


def test_unknown_server_rejected():
    with pytest.raises(ValueError):
        asyncio.run(call_remote_tool("telepathy", "port_scan", {"target": "localhost"}))
