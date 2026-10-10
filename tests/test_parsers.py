"""Tests for the output parsers, using small captured samples of real output."""

import pytest

from recon.core.parsers import (
    parse_nmap_xml,
    parse_nuclei_jsonl,
    parse_subfinder_lines,
    parse_whois,
)

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.25"/>
      </port>
      <port protocol="tcp" portid="81">
        <state state="closed"/>
        <service name="hosts2-ns"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml_extracts_open_ports():
    result = parse_nmap_xml(NMAP_XML)
    assert result["open_port_count"] == 2
    ports = {p["port"] for p in result["open_ports"]}
    assert ports == {22, 80}
    ssh = next(p for p in result["open_ports"] if p["port"] == 22)
    assert ssh["service"] == "ssh"
    assert ssh["product"] == "OpenSSH"
    assert ssh["version"] == "9.6"
    assert ssh["host"] == "127.0.0.1"


def test_parse_nmap_xml_excludes_closed_ports():
    result = parse_nmap_xml(NMAP_XML)
    assert all(p["state"] == "open" for p in result["open_ports"])
    assert 81 not in {p["port"] for p in result["open_ports"]}


def test_parse_nmap_xml_rejects_garbage():
    with pytest.raises(ValueError):
        parse_nmap_xml("not xml at all <<<")


NUCLEI_JSONL = """
{"template-id":"tls-version","info":{"name":"TLS Version","severity":"info"},"matched-at":"localhost:443","type":"ssl"}
{"template-id":"CVE-2021-1234","info":{"name":"Nasty RCE","severity":"critical"},"matched-at":"localhost:80","type":"http"}
{"template-id":"xss-reflected","info":{"name":"Reflected XSS","severity":"medium"},"matched-at":"localhost:80","type":"http"}
not-json-skip-me
"""


def test_parse_nuclei_jsonl_sorts_by_severity():
    findings = parse_nuclei_jsonl(NUCLEI_JSONL)
    assert len(findings) == 3  # the non-JSON line is skipped
    assert [f["severity"] for f in findings] == ["critical", "medium", "info"]
    assert findings[0]["template_id"] == "CVE-2021-1234"
    assert findings[0]["name"] == "Nasty RCE"


def test_parse_nuclei_jsonl_empty():
    assert parse_nuclei_jsonl("") == []


def test_parse_subfinder_dedupes_and_sorts():
    raw = "b.example.com\nA.example.com\nb.example.com\n\n  c.example.com.  \n"
    assert parse_subfinder_lines(raw) == [
        "a.example.com",
        "b.example.com",
        "c.example.com",
    ]


WHOIS = """
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2026-08-13T04:00:00Z
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
"""


def test_parse_whois_extracts_common_fields():
    result = parse_whois(WHOIS)
    assert result["registrar"] == "Example Registrar, Inc."
    assert result["creation_date"] == "1995-08-14T04:00:00Z"
    assert result["expiry_date"] == "2026-08-13T04:00:00Z"
    assert result["name_servers"] == ["a.iana-servers.net", "b.iana-servers.net"]


def test_parse_whois_handles_missing_fields():
    result = parse_whois("No useful data here\n")
    assert result["registrar"] is None
    assert result["name_servers"] == []
