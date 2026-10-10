"""Tests for the leaf MCP server tool functions (nmap, nuclei, osint).

The real scanners are not installed in CI, so these tests:

1. Prove the authorization gate fires *before* any command runs, and that a
   refusal comes back as a structured ``authorized=False`` envelope rather
   than an opaque error.
2. Exercise the authorize -> run -> parse -> envelope path by monkeypatching
   ``run_command`` / the DNS resolver with captured output.

The orchestrator (which is an MCP client of these servers) is covered in
test_orchestrator.py and test_client.py.
"""

import pytest

from recon.core.runner import CommandResult
from recon.servers import nmap_server, nuclei_server, osint_server
from recon.servers._common import envelope


def _fake_result(stdout: str = "", returncode: int = 0) -> CommandResult:
    return CommandResult(
        command=("fake",),
        returncode=returncode,
        stdout=stdout,
        stderr="",
        duration_s=0.01,
        timed_out=False,
    )


def _boom(*args, **kwargs):  # pragma: no cover - must never be called
    raise AssertionError("run_command was called for an unauthorized target")


# --------------------------------------------------------------------------
# The authorization gate fires before anything runs, and refuses structurally
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "call",
    [
        lambda: nmap_server.port_scan("example.com"),
        lambda: nmap_server.service_detect("8.8.8.8"),
        lambda: nuclei_server.vuln_scan("scanme.nmap.org"),
        lambda: osint_server.find_subdomains("example.com"),
        lambda: osint_server.dns_records("example.com"),
        lambda: osint_server.whois_lookup("example.com"),
    ],
)
def test_unauthorized_target_refused_before_running(monkeypatch, call):
    monkeypatch.setattr(nmap_server, "run_command", _boom)
    monkeypatch.setattr(nuclei_server, "run_command", _boom)
    monkeypatch.setattr(osint_server, "run_command", _boom)
    out = call()
    assert out["authorized"] is False
    assert out["result"] is None
    assert "allowlist" in out["error"].lower()


# --------------------------------------------------------------------------
# nmap server
# --------------------------------------------------------------------------

NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="nginx"/></port></ports></host></nmaprun>"""


def test_port_scan_authorized_path(monkeypatch):
    monkeypatch.setattr(nmap_server, "run_command", lambda *a, **k: _fake_result(NMAP_XML))
    out = nmap_server.port_scan("localhost")
    assert out["authorized"] is True
    assert out["target"] == "localhost"
    assert out["result"]["open_port_count"] == 1
    assert out["result"]["open_ports"][0]["port"] == 80


def test_port_scan_empty_output_is_safe(monkeypatch):
    monkeypatch.setattr(nmap_server, "run_command", lambda *a, **k: _fake_result(""))
    out = nmap_server.port_scan("127.0.0.1")
    assert out["result"]["open_port_count"] == 0


# --------------------------------------------------------------------------
# nuclei server
# --------------------------------------------------------------------------

def test_vuln_scan_builds_url_from_canonical_host(monkeypatch):
    captured = {}

    def fake_run(cmd, **k):
        captured["cmd"] = cmd
        return _fake_result('{"template-id":"x","info":{"severity":"high","name":"X"},"matched-at":"localhost"}')

    monkeypatch.setattr(nuclei_server, "run_command", fake_run)
    out = nuclei_server.vuln_scan("http://localhost/some/path", port=3000)
    # URL is rebuilt from the authorized host, not the raw input path.
    assert "http://localhost:3000" in captured["cmd"]
    assert out["result"]["finding_count"] == 1
    assert out["result"]["findings"][0]["severity"] == "high"


def test_vuln_scan_rejects_bad_scheme(monkeypatch):
    monkeypatch.setattr(nuclei_server, "run_command", _boom)
    with pytest.raises(ValueError):
        nuclei_server.vuln_scan("localhost", scheme="gopher")


def test_vuln_scan_rejects_unknown_severity(monkeypatch):
    monkeypatch.setattr(nuclei_server, "run_command", _boom)
    with pytest.raises(ValueError):
        nuclei_server.vuln_scan("localhost", severity="spicy")


def test_vuln_scan_rejects_bad_port(monkeypatch):
    monkeypatch.setattr(nuclei_server, "run_command", _boom)
    with pytest.raises(ValueError):
        nuclei_server.vuln_scan("localhost", port=99999)


# --------------------------------------------------------------------------
# osint server
# --------------------------------------------------------------------------

def test_find_subdomains_authorized_path(monkeypatch):
    monkeypatch.setattr(
        osint_server, "run_command",
        lambda *a, **k: _fake_result("a.localhost\nb.localhost\n"),
    )
    out = osint_server.find_subdomains("localhost")
    assert out["result"]["count"] == 2
    assert out["result"]["subdomains"] == ["a.localhost", "b.localhost"]


def test_dns_records_handles_no_answer(monkeypatch):
    import dns.resolver

    def fake_resolve(self, host, rtype):
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)
    out = osint_server.dns_records("localhost", record_types=["A", "MX"])
    assert out["result"]["records"] == {"A": [], "MX": []}


# --------------------------------------------------------------------------
# envelope helper
# --------------------------------------------------------------------------

def test_envelope_with_command_result():
    env = envelope("nmap", "localhost", {"x": 1}, command=_fake_result("out"))
    assert env["tool"] == "nmap"
    assert env["target"] == "localhost"
    assert env["authorized"] is True
    assert env["command"] == ["fake"]
    assert env["meta"]["returncode"] == 0
    assert env["result"] == {"x": 1}
    assert env["error"] is None


def test_envelope_error_shape():
    env = envelope("nmap", None, None, authorized=False, error="nope")
    assert env["authorized"] is False
    assert env["error"] == "nope"
    assert env["result"] is None
