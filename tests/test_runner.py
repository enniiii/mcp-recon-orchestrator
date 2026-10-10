"""Tests for the command runner.

Uses the current Python interpreter as a stand-in process so the tests run
anywhere without depending on nmap/nuclei being installed.
"""

import sys

import pytest

from recon.core.runner import (
    CommandResult,
    ToolNotInstalled,
    run_command,
)


def test_successful_command():
    result = run_command([sys.executable, "-c", "print('hello')"], timeout=10)
    assert isinstance(result, CommandResult)
    assert result.ok is True
    assert result.returncode == 0
    assert "hello" in result.stdout
    assert result.timed_out is False


def test_nonzero_exit_is_not_raised():
    result = run_command([sys.executable, "-c", "import sys; sys.exit(3)"], timeout=10)
    assert result.returncode == 3
    assert result.ok is False
    assert result.timed_out is False


def test_stderr_is_captured():
    result = run_command(
        [sys.executable, "-c", "import sys; sys.stderr.write('boom')"],
        timeout=10,
    )
    assert "boom" in result.stderr


def test_timeout_kills_and_flags():
    result = run_command(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout=0.5,
    )
    assert result.timed_out is True
    assert result.ok is False
    assert result.returncode is None
    assert "timed out" in result.stderr.lower()


def test_missing_binary_raises():
    with pytest.raises(ToolNotInstalled):
        run_command(["definitely-not-a-real-binary-xyz"], timeout=5)


def test_empty_command_rejected():
    with pytest.raises(ValueError):
        run_command([], timeout=5)


def test_nonpositive_timeout_rejected():
    with pytest.raises(ValueError):
        run_command([sys.executable, "-c", "pass"], timeout=0)


def test_as_dict_is_json_friendly():
    result = run_command([sys.executable, "-c", "print('x')"], timeout=10)
    d = result.as_dict()
    assert d["ok"] is True
    assert d["returncode"] == 0
    assert isinstance(d["command"], list)
    assert isinstance(d["duration_s"], float)
