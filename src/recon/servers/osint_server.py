"""MCP server exposing passive OSINT lookups.

Tools:
    find_subdomains - enumerate subdomains with subfinder (passive sources)
    dns_records     - resolve common DNS record types
    whois_lookup    - registration details via the whois CLI

Everything here is passive: it queries third-party sources and public
resolvers, it does not send packets to the target itself. Targets are still
authorized first, so the "authorized targets only" rule holds uniformly
across the whole toolkit.
"""

from __future__ import annotations

import dns.resolver

from mcp.server.mcpserver import MCPServer

from recon.core.allowlist import assert_authorized
from recon.core.parsers import parse_subfinder_lines, parse_whois
from recon.core.runner import run_command
from recon.servers._common import envelope, guarded

mcp = MCPServer("osint-recon")

_SUBFINDER_TIMEOUT_S = 180.0
_WHOIS_TIMEOUT_S = 60.0
_DEFAULT_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
_DNS_TIMEOUT_S = 5.0


@mcp.tool()
@guarded
def find_subdomains(domain: str) -> dict:
    """Enumerate subdomains of an authorized domain using subfinder.

    An unauthorized domain returns an ``authorized=False`` envelope.
    """
    host = assert_authorized(domain)
    command = ["subfinder", "-d", host, "-silent"]
    result = run_command(command, timeout=_SUBFINDER_TIMEOUT_S)
    subdomains = parse_subfinder_lines(result.stdout)
    payload = {"subdomains": subdomains, "count": len(subdomains)}
    return envelope("subfinder", host, payload, command=result)


@mcp.tool()
@guarded
def dns_records(domain: str, record_types: list[str] | None = None) -> dict:
    """Resolve DNS records for an authorized domain.

    Args:
        domain: Domain to resolve. Must be on the allowlist.
        record_types: Record types to query. Defaults to A, AAAA, MX, NS,
            TXT, CNAME.

    Returns:
        An envelope whose ``result`` maps each record type to its values (an
        empty list when there is no such record). An unauthorized domain
        returns an ``authorized=False`` envelope.
    """
    host = assert_authorized(domain)
    types = [t.strip().upper() for t in (record_types or _DEFAULT_RECORD_TYPES) if t.strip()]

    resolver = dns.resolver.Resolver()
    resolver.lifetime = _DNS_TIMEOUT_S
    resolver.timeout = _DNS_TIMEOUT_S

    records: dict[str, list[str]] = {}
    for rtype in types:
        try:
            answers = resolver.resolve(host, rtype)
            records[rtype] = sorted(r.to_text() for r in answers)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            records[rtype] = []
        except dns.exception.DNSException as exc:
            records[rtype] = [f"error: {exc.__class__.__name__}"]

    return envelope("dns", host, {"records": records}, command=["dns-resolver", host])


@mcp.tool()
@guarded
def whois_lookup(domain: str) -> dict:
    """Look up WHOIS registration details for an authorized domain.

    An unauthorized domain returns an ``authorized=False`` envelope.
    """
    host = assert_authorized(domain)
    command = ["whois", host]
    result = run_command(command, timeout=_WHOIS_TIMEOUT_S)
    parsed = parse_whois(result.stdout)
    return envelope("whois", host, parsed, command=result)


if __name__ == "__main__":
    mcp.run()
