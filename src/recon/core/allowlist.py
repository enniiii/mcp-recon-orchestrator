"""Target allowlist — the safety core of the toolkit.

This module decides, for a single target string, whether a recon tool is
permitted to touch it. The design rule is **deny by default**: a target is
authorized only if it canonicalizes to something explicitly on the allowlist.
Anything ambiguous, malformed, or clever is refused.

The allowlist covers exactly three kinds of target:

* loopback  (``localhost``, ``127.0.0.0/8``, ``::1``)
* a Docker lab network / host you run yourself
* a single DuckDNS subdomain you own

The authorization decision is made on the *literal* host in the target
string. We deliberately do **not** resolve DNS to make the decision, because
resolution is attacker-influenced (DNS rebinding) and would turn the allowlist
into a time-of-check/time-of-use hole.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field

__all__ = [
    "AllowlistPolicy",
    "TargetNotAuthorized",
    "assert_authorized",
    "canonical_host",
    "is_authorized",
    "load_policy_from_env",
]

# Hostnames that always resolve to the local machine. Matched exactly, never
# as a substring, so "localhost.evil.com" does not sneak through.
_LOOPBACK_HOSTNAMES = frozenset({"localhost"})

# Loopback IP ranges, always permitted.
_LOOPBACK_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


class TargetNotAuthorized(Exception):
    """Raised when a target is not on the allowlist.

    MCP tools let this propagate so the caller (and the AI agent driving it)
    gets a clear, explicit refusal instead of an accidental scan.
    """


@dataclass(frozen=True)
class AllowlistPolicy:
    """An immutable set of authorized targets.

    Attributes:
        hostnames: Exact, lowercased hostnames (no trailing dot) that are
            authorized. Loopback names are always included.
        networks: IP networks that are authorized. Loopback ranges are always
            included.
    """

    hostnames: frozenset[str] = field(default_factory=frozenset)
    networks: tuple[ipaddress._BaseNetwork, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        merged_hosts = frozenset(
            h.strip().rstrip(".").lower()
            for h in self.hostnames
            if h.strip()
        ) | _LOOPBACK_HOSTNAMES
        merged_nets = tuple(self.networks) + _LOOPBACK_NETWORKS
        # dataclass is frozen, so assign through object.__setattr__.
        object.__setattr__(self, "hostnames", merged_hosts)
        object.__setattr__(self, "networks", merged_nets)

    def describe(self) -> str:
        """Human-readable summary for error messages and the MCP banner."""
        hosts = ", ".join(sorted(self.hostnames)) or "(none)"
        nets = ", ".join(str(n) for n in self.networks) or "(none)"
        return f"hostnames: {hosts} | networks: {nets}"


def canonical_host(target: str) -> str:
    """Reduce a target string to the bare host it refers to.

    Strips scheme, userinfo, path/query/fragment, and port, then lowercases
    and removes a trailing dot. Handles bracketed IPv6 literals.

    Raises:
        ValueError: if no host can be extracted.
    """
    if not isinstance(target, str):
        raise ValueError("target must be a string")

    t = target.strip()
    if not t:
        raise ValueError("empty target")

    # Strip a scheme such as "http://" or "ssh://".
    if "://" in t:
        t = t.split("://", 1)[1]
    elif t.startswith("//"):
        t = t[2:]

    # Strip path, query, and fragment — the host is only what comes first.
    for sep in ("/", "?", "#"):
        t = t.split(sep, 1)[0]

    # Strip userinfo ("user:pass@host"). The real host is after the last '@',
    # so "127.0.0.1@evil.com" canonicalizes to evil.com, not 127.0.0.1.
    if "@" in t:
        t = t.rsplit("@", 1)[1]

    if not t:
        raise ValueError("no host in target")

    # Separate host from port. Bracketed IPv6 first: "[::1]:8080".
    if t.startswith("["):
        end = t.find("]")
        if end == -1:
            raise ValueError("unterminated IPv6 literal")
        host = t[1:end]
    elif t.count(":") == 1:
        # Exactly one colon => host:port (a bare IPv6 address has >= 2 colons).
        host = t.split(":", 1)[0]
    else:
        host = t

    host = host.strip().rstrip(".").lower()
    if not host:
        raise ValueError("empty host after normalization")
    return host


def _matches(host: str, policy: AllowlistPolicy) -> bool:
    """True if a canonical host is permitted by the policy."""
    # If the host parses as an IP, decide purely by network membership. This
    # is the only path that treats the value as an address; alternate
    # encodings (decimal "2130706433", hex "0x7f000001") do not parse here and
    # therefore fall through to the hostname check, which they also fail.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host in policy.hostnames
    return any(ip in net for net in policy.networks)


def is_authorized(target: str, policy: AllowlistPolicy | None = None) -> bool:
    """Return whether *target* is on the allowlist. Never raises.

    Any malformed or unparseable target returns ``False`` (deny by default).
    """
    if policy is None:
        policy = load_policy_from_env()
    try:
        host = canonical_host(target)
    except ValueError:
        return False
    return _matches(host, policy)


def assert_authorized(
    target: str, policy: AllowlistPolicy | None = None
) -> str:
    """Authorize *target* or raise.

    Returns the canonical host on success so callers can scan a normalized
    value rather than the raw user string.

    Raises:
        TargetNotAuthorized: if the target is not on the allowlist.
    """
    if policy is None:
        policy = load_policy_from_env()
    if not is_authorized(target, policy):
        raise TargetNotAuthorized(
            f"Refusing to act on {target!r}: not on the allowlist. "
            f"Authorized targets -> {policy.describe()}. "
            f"This toolkit scans authorized targets only."
        )
    return canonical_host(target)


def _parse_network(value: str) -> ipaddress._BaseNetwork | None:
    """Parse a single CIDR or bare-IP entry into a network, or None."""
    value = value.strip()
    if not value:
        return None
    try:
        # strict=False so "10.10.0.5/24" is accepted as its enclosing network.
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def load_policy_from_env(env: dict[str, str] | None = None) -> AllowlistPolicy:
    """Build an :class:`AllowlistPolicy` from environment variables.

    Variables (all optional; loopback is always allowed):

    * ``RECON_ALLOWED_HOSTS`` — comma-separated hostnames, e.g. your DuckDNS
      subdomain ``mylab.duckdns.org``.
    * ``RECON_ALLOWED_NETWORKS`` — comma-separated IPs/CIDRs for your Docker
      lab, e.g. ``172.18.0.0/16,192.168.56.10``.
    """
    env = os.environ if env is None else env

    hosts = frozenset(
        part.strip().lower()
        for part in env.get("RECON_ALLOWED_HOSTS", "").split(",")
        if part.strip()
    )

    networks: list[ipaddress._BaseNetwork] = []
    for part in env.get("RECON_ALLOWED_NETWORKS", "").split(","):
        net = _parse_network(part)
        if net is not None:
            networks.append(net)

    return AllowlistPolicy(hostnames=hosts, networks=tuple(networks))
