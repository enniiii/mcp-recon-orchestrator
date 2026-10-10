"""Safety core: target authorization, command execution, and output parsing.

Everything an MCP tool does to a network target must pass through
``allowlist.assert_authorized`` first. That function is the single
choke point this project is built around.
"""

from recon.core.allowlist import (
    AllowlistPolicy,
    TargetNotAuthorized,
    assert_authorized,
    canonical_host,
    is_authorized,
    load_policy_from_env,
)

__all__ = [
    "AllowlistPolicy",
    "TargetNotAuthorized",
    "assert_authorized",
    "canonical_host",
    "is_authorized",
    "load_policy_from_env",
]
