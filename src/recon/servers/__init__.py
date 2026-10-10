"""MCP server entry points.

Each module here exposes a small set of recon tools over MCP (stdio). Every
tool authorizes its target through ``recon.core.allowlist`` before doing
anything, so the allowlist is the single gate the whole toolkit depends on.
"""
