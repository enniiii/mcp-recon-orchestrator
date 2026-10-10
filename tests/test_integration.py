"""Integration tests that run real scanners against the Docker lab.

These are skipped by default (see the ``-m "not integration"`` default in
pyproject.toml). Run them inside the lab, where nmap/nuclei/subfinder are
installed and the Juice Shop target is on the allowlist:

    docker compose up -d --build
    docker compose exec recon pytest -m integration

The target host defaults to ``juiceshop`` (the compose service name) and can
be overridden with RECON_TARGET.
"""

import asyncio
import os
import shutil

import pytest

from recon.servers import nmap_server, nuclei_server, orchestrator_server

pytestmark = pytest.mark.integration

TARGET = os.environ.get("RECON_TARGET", "juiceshop")
JUICE_PORT = int(os.environ.get("RECON_TARGET_PORT", "3000"))


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed")
def test_port_scan_finds_juiceshop_port():
    out = nmap_server.port_scan(TARGET, ports="1-4000")
    open_ports = {p["port"] for p in out["result"]["open_ports"]}
    assert JUICE_PORT in open_ports


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei not installed")
def test_vuln_scan_runs_against_juiceshop():
    out = nuclei_server.vuln_scan(TARGET, port=JUICE_PORT)
    # Juice Shop is intentionally vulnerable; at minimum the scan completes
    # and returns a well-formed findings list.
    assert "findings" in out["result"]
    assert isinstance(out["result"]["findings"], list)


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed")
def test_full_assessment_chains_over_mcp():
    # Drives the leaf servers as real MCP subprocesses and chains them.
    out = asyncio.run(orchestrator_server.full_assessment(TARGET))
    assert out["workflow"] == "full_assessment"
    assert out["authorized"] is True
    assert JUICE_PORT in out["summary"]["open_ports"]
    # Every step reports a boolean ok, whether or not its tool is present.
    assert all(isinstance(s["ok"], bool) for s in out["steps"])
