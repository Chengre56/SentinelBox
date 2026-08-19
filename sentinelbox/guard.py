from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from sentinelbox.exceptions import PathSecurityError
from sentinelbox.models import CommandRequest, GuardDecision
from sentinelbox.platform import get_platform_adapter
from sentinelbox.policies import PolicyEngine


class CommandGuard:
    """Security verification firewall for file operations and process invocations."""

    def __init__(self, policy_engine: Optional[PolicyEngine] = None) -> None:
        self.policy_engine = policy_engine or PolicyEngine()
        self.platform_adapter = get_platform_adapter()

    def inspect_command(self, request: CommandRequest) -> GuardDecision:
        return self.policy_engine.evaluate_command(request)

    def validate_path_within_root(self, target_path: Path | str, root_dir: Path) -> Path:
        """
        Guarantees that target_path resolves strictly inside root_dir.
        Defends against directory traversal, symlink escapes, Windows drive escapes, and UNC paths.
        """
        str_path = str(target_path)
        if not self.platform_adapter.validate_path_safety(str_path):
            raise PathSecurityError(f"Path contains illegal characters: {str_path}")

        resolved_root = root_dir.resolve()
        
        # Handle relative vs absolute
        candidate = Path(target_path)
        if candidate.is_absolute():
            # If absolute, verify it begins with root_dir
            try:
                candidate_resolved = candidate.resolve()
                candidate_resolved.relative_to(resolved_root)
                return candidate_resolved
            except (ValueError, RuntimeError):
                raise PathSecurityError(f"Absolute path '{target_path}' escapes sandbox root '{resolved_root}'")

        # Resolve combined path
        combined = (root_dir / candidate).resolve()
        try:
            combined.relative_to(resolved_root)
        except ValueError:
            raise PathSecurityError(f"Path traversal detected: '{target_path}' escapes sandbox root '{resolved_root}'")

        # Prevent symlink resolution escaping the root
        if combined.is_symlink():
            symlink_target = Path(os.path.realpath(combined))
            try:
                symlink_target.relative_to(resolved_root)
            except ValueError:
                raise PathSecurityError(f"Symlink at '{target_path}' points outside sandbox to '{symlink_target}'")

        return combined