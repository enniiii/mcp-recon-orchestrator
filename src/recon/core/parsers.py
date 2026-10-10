"""Parsers that turn raw recon-tool output into clean, JSON-friendly dicts.

Each function is pure: raw text in, plain dict/list out. That keeps them
trivial to unit-test without any scanner installed, and it keeps the MCP
servers thin — they shell out, hand the bytes here, and return the result.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

__all__ = [
    "parse_nmap_xml",
    "parse_nuclei_jsonl",
    "parse_subfinder_lines",
    "parse_whois",
]


def parse_nmap_xml(xml_text: str) -> dict:
    """Parse nmap XML output (``nmap -oX -``) into a summary dict.

    Returns a dict with the resolved host and a list of ports, each carrying
    state and any detected service/product/version. Malformed XML raises
    ``ValueError`` so the caller can surface a clear error.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid nmap XML: {exc}") from exc

    hosts: list[dict] = []
    for host_el in root.findall("host"):
        addr = ""
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") in ("ipv4", "ipv6"):
                addr = addr_el.get("addr", "")
                break

        status_el = host_el.find("status")
        state = status_el.get("state", "unknown") if status_el is not None else "unknown"

        ports: list[dict] = []
        for port_el in host_el.findall("./ports/port"):
            port_state_el = port_el.find("state")
            service_el = port_el.find("service")
            ports.append(
                {
                    "port": int(port_el.get("portid", "0")),
                    "protocol": port_el.get("protocol", ""),
                    "state": (
                        port_state_el.get("state", "")
                        if port_state_el is not None
                        else ""
                    ),
                    "service": (
                        service_el.get("name", "")
                        if service_el is not None
                        else ""
                    ),
                    "product": (
                        service_el.get("product", "")
                        if service_el is not None
                        else ""
                    ),
                    "version": (
                        service_el.get("version", "")
                        if service_el is not None
                        else ""
                    ),
                }
            )
        hosts.append({"address": addr, "state": state, "ports": ports})

    open_ports = [
        {**p, "host": h["address"]}
        for h in hosts
        for p in h["ports"]
        if p["state"] == "open"
    ]
    return {
        "hosts": hosts,
        "open_ports": open_ports,
        "open_port_count": len(open_ports),
    }


def parse_nuclei_jsonl(text: str) -> list[dict]:
    """Parse nuclei JSONL output (``nuclei -jsonl``) into a findings list.

    Each non-empty line is a JSON object. Lines that fail to parse are
    skipped rather than aborting the whole run. Severity is normalized to
    lowercase and findings are sorted most-severe first.
    """
    severity_rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
        "unknown": 5,
    }
    findings: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {}) if isinstance(obj, dict) else {}
        severity = str(info.get("severity", "unknown")).lower()
        findings.append(
            {
                "template_id": obj.get("template-id", obj.get("templateID", "")),
                "name": info.get("name", ""),
                "severity": severity,
                "matched_at": obj.get("matched-at", obj.get("host", "")),
                "type": obj.get("type", ""),
            }
        )
    findings.sort(key=lambda f: severity_rank.get(f["severity"], 99))
    return findings


def parse_subfinder_lines(text: str) -> list[str]:
    """Parse subfinder's plain line output into sorted, unique subdomains."""
    seen = {
        line.strip().rstrip(".").lower()
        for line in text.splitlines()
        if line.strip()
    }
    return sorted(seen)


def parse_whois(text: str) -> dict:
    """Extract a handful of common fields from freeform WHOIS text.

    WHOIS has no standard schema, so this is best-effort: it pulls the fields
    that show up most often and returns the raw text alongside them.
    """
    fields = {
        "registrar": ("registrar:",),
        "creation_date": ("creation date:", "created:", "registered on:"),
        "expiry_date": ("registry expiry date:", "expiry date:", "expires on:"),
        "name_servers": ("name server:", "nserver:"),
    }
    result: dict = {
        "registrar": None,
        "creation_date": None,
        "expiry_date": None,
        "name_servers": [],
    }
    for raw in text.splitlines():
        line = raw.strip()
        low = line.lower()
        for key, prefixes in fields.items():
            for prefix in prefixes:
                if low.startswith(prefix):
                    value = line[len(prefix):].strip()
                    if not value:
                        continue
                    if key == "name_servers":
                        ns = value.lower().split()[0]
                        if ns not in result["name_servers"]:
                            result["name_servers"].append(ns)
                    elif result[key] is None:
                        result[key] = value
                    break
    return result
