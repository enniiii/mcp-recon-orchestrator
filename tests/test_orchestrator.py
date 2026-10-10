"""Tests for the orchestrator's workflow logic.

The transport (``call_remote_tool``) is stubbed so these run fast and
hermetically; the real transport is covered in test_client.py. Here we check
that the orchestrator authorizes first, chains the right calls, extracts open
ports, picks a web port, and stays up when a step fails.
"""

import asyncio

from recon.servers import orchestrator_server


def _envelope(tool, result, *, authorized=True, error=None):
    return {
        "tool": tool,
        "target": "localhost",
        "authorized": authorized,
        "command": None,
        "meta": {},
        "result": result,
        "error": error,
    }


def _install_fake(monkeypatch, responses, recorder=None):
    """Patch call_remote_tool with an async fake keyed by (server, tool)."""

    async def fake(server, tool, arguments=None):
        if recorder is not None:
            recorder.append((server, tool, arguments))
        return responses[(server, tool)]

    monkeypatch.setattr(orchestrator_server, "call_remote_tool", fake)


def test_quick_recon_aggregates(monkeypatch):
    responses = {
        ("nmap", "port_scan"): _envelope(
            "port_scan", {"open_ports": [{"port": 22}, {"port": 80}]}
        ),
        ("osint", "dns_records"): _envelope("dns", {"records": {"A": ["127.0.0.1"]}}),
    }
    _install_fake(monkeypatch, responses)

    out = asyncio.run(orchestrator_server.quick_recon("localhost"))
    assert out["authorized"] is True
    assert out["target"] == "localhost"
    assert out["summary"]["open_ports"] == [22, 80]
    assert [s["step"] for s in out["steps"]] == ["port_scan", "dns_records"]
    assert all(s["ok"] for s in out["steps"])


def test_quick_recon_refuses_without_calling(monkeypatch):
    called = []

    async def fake(*a, **k):  # pragma: no cover - must not be called
        called.append(a)
        return {}

    monkeypatch.setattr(orchestrator_server, "call_remote_tool", fake)

    out = asyncio.run(orchestrator_server.quick_recon("example.com"))
    assert out["authorized"] is False
    assert out["steps"] == []
    assert "allowlist" in out["error"].lower()
    assert called == []  # no subprocess / MCP call was made


def test_full_assessment_chains_and_picks_web_port(monkeypatch):
    calls = []
    responses = {
        ("nmap", "port_scan"): _envelope(
            "port_scan", {"open_ports": [{"port": 80}, {"port": 3000}]}
        ),
        ("nmap", "service_detect"): _envelope("service_detect", {"open_ports": []}),
        ("nuclei", "vuln_scan"): _envelope("vuln_scan", {"findings": []}),
        ("osint", "find_subdomains"): _envelope("subfinder", {"subdomains": []}),
        ("osint", "dns_records"): _envelope("dns", {"records": {}}),
        ("osint", "whois_lookup"): _envelope("whois", {"registrar": None}),
    }
    _install_fake(monkeypatch, responses, recorder=calls)

    out = asyncio.run(orchestrator_server.full_assessment("localhost"))
    steps = [s["step"] for s in out["steps"]]
    assert steps == [
        "port_scan",
        "service_detect",
        "vuln_scan",
        "find_subdomains",
        "dns_records",
        "whois_lookup",
    ]
    # Prefers 3000 (Juice Shop) over 80 for the web scan.
    assert out["summary"]["web_port_scanned"] == 3000
    vuln_call = next(c for c in calls if c[1] == "vuln_scan")
    assert vuln_call[2]["port"] == 3000
    # service_detect was asked about exactly the open ports.
    sd_call = next(c for c in calls if c[1] == "service_detect")
    assert sd_call[2]["ports"] == "80,3000"
    assert out["summary"]["steps_ok"] == 6


def test_full_assessment_skips_service_detect_when_no_open_ports(monkeypatch):
    calls = []
    responses = {
        ("nmap", "port_scan"): _envelope("port_scan", {"open_ports": []}),
        ("nuclei", "vuln_scan"): _envelope("vuln_scan", {"findings": []}),
        ("osint", "find_subdomains"): _envelope("subfinder", {"subdomains": []}),
        ("osint", "dns_records"): _envelope("dns", {"records": {}}),
        ("osint", "whois_lookup"): _envelope("whois", {"registrar": None}),
    }
    _install_fake(monkeypatch, responses, recorder=calls)

    out = asyncio.run(orchestrator_server.full_assessment("localhost"))
    steps = [s["step"] for s in out["steps"]]
    assert "service_detect" not in steps
    assert out["summary"]["web_port_scanned"] is None


def test_step_marks_refusal_and_error_as_not_ok(monkeypatch):
    responses = {
        ("nmap", "port_scan"): _envelope("port_scan", None, authorized=False, error="refused"),
        ("osint", "dns_records"): _envelope("dns", None, error="whoops"),
    }
    _install_fake(monkeypatch, responses)

    out = asyncio.run(orchestrator_server.quick_recon("localhost"))
    assert all(s["ok"] is False for s in out["steps"])


def test_step_captures_transport_exception(monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("connection lost")

    monkeypatch.setattr(orchestrator_server, "call_remote_tool", boom)
    out = asyncio.run(orchestrator_server.quick_recon("localhost"))
    assert all(s["ok"] is False for s in out["steps"])
    assert "RuntimeError" in out["steps"][0]["error"]


def test_open_ports_handles_missing_data():
    assert orchestrator_server._open_ports({"ok": False, "data": None}) == []
    assert orchestrator_server._open_ports({"data": {"result": None}}) == []
