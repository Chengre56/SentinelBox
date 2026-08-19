from pathlib import Path
import pytest

from sentinelbox.exceptions import PathSecurityError
from sentinelbox.guard import CommandGuard
from sentinelbox.models import CommandRequest, GuardAction, GuardSeverity
from sentinelbox.policies import PolicyEngine


def test_guard_allow_safe_commands() -> None:
    guard = CommandGuard()
    req = CommandRequest(command=["python", "-m", "pytest"])
    decision = guard.inspect_command(req)
    assert decision.action == GuardAction.ALLOW
    assert decision.rule_id == "EXEC-ALLOWED"


def test_guard_deny_destructive_commands() -> None:
    guard = CommandGuard()
    req = CommandRequest(command="rm -rf /")
    decision = guard.inspect_command(req)
    assert decision.action == GuardAction.DENY
    assert decision.severity == GuardSeverity.CRITICAL


def test_guard_deny_credential_access() -> None:
    guard = CommandGuard()
    req = CommandRequest(command=["cat", "/home/user/.ssh/id_rsa"])
    decision = guard.inspect_command(req)
    assert decision.action == GuardAction.DENY
    assert decision.rule_id == "SEC-001"


def test_guard_deny_unlisted_executable_in_default_deny() -> None:
    engine = PolicyEngine(default_action=GuardAction.DENY)
    guard = CommandGuard(policy_engine=engine)
    req = CommandRequest(command=["unknown_binary_xyz", "--flag"])
    decision = guard.inspect_command(req)
    assert decision.action == GuardAction.DENY


def test_path_traversal_detection(tmp_path: Path) -> None:
    guard = CommandGuard()
    root = tmp_path / "sandbox"
    root.mkdir()

    # Valid relative path inside root
    safe_path = guard.validate_path_within_root("src/app.py", root)
    assert safe_path == (root / "src/app.py").resolve()

    # Illegal directory traversal escape
    with pytest.raises(PathSecurityError):
        guard.validate_path_within_root("../../etc/passwd", root)