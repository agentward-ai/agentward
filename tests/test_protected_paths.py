"""Tests for protected path invariants (fix #3).

Verifies that tool calls referencing sensitive filesystem paths
(~/.ssh, ~/.gnupg, ~/.aws, etc.) are always blocked regardless
of policy configuration.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from agentward.policy.engine import EvaluationResult, PolicyEngine
from agentward.policy.protected_paths import (
    PROTECTED_DIRS,
    check_arguments,
    _check_single_value,
)
from agentward.policy.schema import (
    AgentWardPolicy,
    DefaultAction,
    PolicyDecision,
)


class TestCheckArguments:
    """Test the check_arguments function directly."""

    def test_none_arguments(self) -> None:
        assert check_arguments(None) is None

    def test_empty_arguments(self) -> None:
        assert check_arguments({}) is None

    def test_safe_path(self) -> None:
        assert check_arguments({"path": "/tmp/hello.txt"}) is None

    def test_safe_url(self) -> None:
        assert check_arguments({"url": "https://example.com/.ssh/key"}) is None

    def test_ssh_absolute(self) -> None:
        ssh_path = str(Path.home() / ".ssh" / "id_rsa")
        result = check_arguments({"path": ssh_path})
        assert result is not None
        assert "Protected path invariant" in result

    def test_ssh_tilde(self) -> None:
        result = check_arguments({"path": "~/.ssh/id_rsa"})
        assert result is not None
        assert "Protected path invariant" in result

    def test_ssh_directory(self) -> None:
        result = check_arguments({"path": "~/.ssh"})
        assert result is not None

    def test_gnupg(self) -> None:
        result = check_arguments({"path": "~/.gnupg/pubring.kbx"})
        assert result is not None

    def test_aws(self) -> None:
        result = check_arguments({"path": "~/.aws/credentials"})
        assert result is not None

    def test_kube(self) -> None:
        result = check_arguments({"path": "~/.kube/config"})
        assert result is not None

    def test_docker(self) -> None:
        result = check_arguments({"path": "~/.docker/config.json"})
        assert result is not None

    def test_npmrc(self) -> None:
        result = check_arguments({"path": "~/.npmrc"})
        assert result is not None

    def test_netrc(self) -> None:
        result = check_arguments({"path": "~/.netrc"})
        assert result is not None

    def test_nested_argument(self) -> None:
        """Protected paths detected in nested dicts."""
        result = check_arguments({"config": {"key_file": "~/.ssh/id_ed25519"}})
        assert result is not None

    def test_list_argument(self) -> None:
        """Protected paths detected in list arguments."""
        result = check_arguments({"files": ["/tmp/a.txt", "~/.aws/credentials"]})
        assert result is not None

    def test_non_string_values_safe(self) -> None:
        """Non-string values are skipped."""
        assert check_arguments({"count": 42, "flag": True}) is None

    def test_short_strings_safe(self) -> None:
        """Short strings that can't be paths are skipped."""
        assert check_arguments({"x": "ab"}) is None


class TestCheckSingleValue:
    """Test _check_single_value edge cases."""

    def test_relative_path_not_matched(self) -> None:
        """Relative paths without ~ or / are not considered paths."""
        assert _check_single_value("some/file.txt") is None

    def test_dot_dot_traversal_to_ssh(self) -> None:
        """Path traversal with .. that resolves to .ssh is blocked."""
        # Build a path that resolves to ~/.ssh via traversal
        traversal = str(Path.home() / "Documents" / ".." / ".ssh" / "id_rsa")
        result = _check_single_value(traversal)
        assert result is not None


class TestSymlinkResolution:
    """Test that symlinks to protected paths are detected."""

    def test_symlink_to_ssh_detected(self, tmp_path: Path) -> None:
        """A symlink pointing to ~/.ssh is blocked."""
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.exists():
            pytest.skip("~/.ssh does not exist on this machine")

        symlink = tmp_path / "innocent_link"
        symlink.symlink_to(ssh_dir)

        result = check_arguments({"path": str(symlink)})
        assert result is not None
        assert "Protected path invariant" in result

    def test_symlink_to_safe_dir_allowed(self, tmp_path: Path) -> None:
        """A symlink pointing to a safe directory is allowed."""
        safe_dir = tmp_path / "safe"
        safe_dir.mkdir()

        symlink = tmp_path / "link_to_safe"
        symlink.symlink_to(safe_dir)

        result = check_arguments({"path": str(symlink / "file.txt")})
        assert result is None


class TestPolicyEngineIntegration:
    """Test that protected paths are enforced at the policy engine level."""

    def _make_policy(self, default: str = "allow") -> AgentWardPolicy:
        return AgentWardPolicy(
            version="1.0",
            default_action=DefaultAction(default),
            skills={
                "file-manager": {
                    "filesystem": {"read": True, "write": True}
                }
            },
        )

    def test_protected_path_blocked_despite_allow_policy(self) -> None:
        """Even when policy says ALLOW, protected paths are blocked."""
        engine = PolicyEngine(self._make_policy("allow"))
        result = engine.evaluate("filesystem_read", {"path": "~/.ssh/id_rsa"})
        assert result.decision == PolicyDecision.BLOCK
        assert "Protected path invariant" in result.reason

    def test_protected_path_blocked_in_block_default(self) -> None:
        """Protected paths blocked even when default is already block."""
        engine = PolicyEngine(self._make_policy("block"))
        result = engine.evaluate("filesystem_read", {"path": "~/.aws/credentials"})
        assert result.decision == PolicyDecision.BLOCK
        assert "Protected path invariant" in result.reason

    def test_safe_path_allowed_by_policy(self) -> None:
        """Safe paths still evaluated by normal policy rules."""
        engine = PolicyEngine(self._make_policy("allow"))
        result = engine.evaluate("filesystem_read", {"path": "/tmp/data.txt"})
        assert result.decision == PolicyDecision.ALLOW

    def test_no_arguments_no_block(self) -> None:
        """Tools called without arguments are not blocked by protected paths."""
        engine = PolicyEngine(self._make_policy("allow"))
        result = engine.evaluate("filesystem_list", None)
        assert result.decision != PolicyDecision.BLOCK or "Protected path" not in result.reason


class TestAllProtectedDirs:
    """Ensure every entry in PROTECTED_DIRS is actually enforced."""

    @pytest.mark.parametrize("protected_dir", PROTECTED_DIRS)
    def test_each_protected_dir(self, protected_dir: str) -> None:
        path = f"~/{protected_dir}"
        result = check_arguments({"path": path})
        assert result is not None, f"Expected {path} to be blocked but it was allowed"
