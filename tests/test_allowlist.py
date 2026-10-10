"""Tests for the target allowlist — the safety core.

These are the tests a reviewer reads first, so they double as the spec:
loopback and configured targets are allowed; everything else, including a
range of spoofing tricks, is refused.
"""

import ipaddress

import pytest

from recon.core.allowlist import (
    AllowlistPolicy,
    TargetNotAuthorized,
    assert_authorized,
    canonical_host,
    is_authorized,
    load_policy_from_env,
)


@pytest.fixture
def policy() -> AllowlistPolicy:
    """A realistic lab policy: loopback + a Docker net + a DuckDNS host."""
    return AllowlistPolicy(
        hostnames=frozenset({"mylab.duckdns.org"}),
        networks=(ipaddress.ip_network("172.18.0.0/16"),),
    )


# --------------------------------------------------------------------------
# canonical_host: reduce any target string to its bare host
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("localhost", "localhost"),
        ("LocalHost", "localhost"),
        ("localhost.", "localhost"),
        ("127.0.0.1", "127.0.0.1"),
        ("http://localhost/admin", "localhost"),
        ("https://mylab.duckdns.org:8443/path?q=1", "mylab.duckdns.org"),
        ("localhost:8080", "localhost"),
        ("[::1]:8080", "::1"),
        ("::1", "::1"),
        ("ssh://user:pass@localhost", "localhost"),
        ("  localhost  ", "localhost"),
    ],
)
def test_canonical_host(raw, expected):
    assert canonical_host(raw) == expected


def test_canonical_host_userinfo_spoof():
    # The host is what follows the last '@', not the decoy before it.
    assert canonical_host("http://127.0.0.1@evil.com/") == "evil.com"


@pytest.mark.parametrize("bad", ["", "   ", "http://", "//", "[::1"])
def test_canonical_host_rejects_garbage(bad):
    with pytest.raises(ValueError):
        canonical_host(bad)


# --------------------------------------------------------------------------
# Allowed targets
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "target",
    [
        "localhost",
        "LOCALHOST",
        "127.0.0.1",
        "127.0.0.1:8080",
        "127.5.5.5",          # anywhere in 127.0.0.0/8
        "::1",
        "[::1]:9000",
        "http://localhost:3000/#/",
        "mylab.duckdns.org",
        "https://mylab.duckdns.org/login",
        "172.18.0.2",          # inside the Docker network
        "172.18.255.254",
    ],
)
def test_authorized_targets(policy, target):
    assert is_authorized(target, policy) is True
    assert assert_authorized(target, policy) == canonical_host(target)


# --------------------------------------------------------------------------
# Refused targets, including spoofing attempts
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "target",
    [
        "example.com",
        "8.8.8.8",
        "scanme.nmap.org",
        "localhost.evil.com",        # substring, not a real match
        "evil.com/localhost",        # path noise
        "mylab.duckdns.org.evil.com",  # suffix spoof
        "notmylab.duckdns.org",
        "http://127.0.0.1@evil.com",  # userinfo decoy
        "2130706433",                # decimal encoding of 127.0.0.1
        "0x7f000001",                # hex encoding of 127.0.0.1
        "172.19.0.1",                # one network over from the lab
        "10.0.0.5",                  # private but not configured
        "169.254.169.254",           # cloud metadata endpoint
        "",                          # empty
        "   ",                       # whitespace
    ],
)
def test_refused_targets(policy, target):
    assert is_authorized(target, policy) is False
    with pytest.raises(TargetNotAuthorized):
        assert_authorized(target, policy)


def test_default_policy_allows_only_loopback():
    empty = AllowlistPolicy()
    assert is_authorized("localhost", empty) is True
    assert is_authorized("127.0.0.1", empty) is True
    assert is_authorized("mylab.duckdns.org", empty) is False
    assert is_authorized("172.18.0.2", empty) is False


# --------------------------------------------------------------------------
# Policy loading from environment
# --------------------------------------------------------------------------

def test_load_policy_from_env_parses_hosts_and_networks():
    policy = load_policy_from_env(
        {
            "RECON_ALLOWED_HOSTS": "mylab.duckdns.org, Other.Example ",
            "RECON_ALLOWED_NETWORKS": "172.18.0.0/16, 192.168.56.10, junk",
        }
    )
    assert "mylab.duckdns.org" in policy.hostnames
    assert "other.example" in policy.hostnames       # lowercased + trimmed
    assert "localhost" in policy.hostnames           # loopback always present
    assert is_authorized("172.18.0.9", policy)
    assert is_authorized("192.168.56.10", policy)
    assert not is_authorized("192.168.56.11", policy)  # /32 from bare IP


def test_load_policy_from_env_empty_is_loopback_only():
    policy = load_policy_from_env({})
    assert is_authorized("localhost", policy)
    assert not is_authorized("example.com", policy)


def test_describe_mentions_authorized_targets(policy):
    text = policy.describe()
    assert "localhost" in text
    assert "mylab.duckdns.org" in text
    assert "172.18.0.0/16" in text
