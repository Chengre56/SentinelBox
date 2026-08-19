from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from sentinelbox.exceptions import PolicyError
from sentinelbox.models import HashMode, NetworkMode, ShellType


@dataclass
class ExecutionConfig:
    shell: ShellType = ShellType.AUTO
    timeout_seconds: float = 120.0
    max_output_bytes: int = 10 * 1024 * 1024  # 10 MB
    max_created_files: int = 10000
    max_file_size_bytes: int = 100 * 1024 * 1024  # 100 MB


@dataclass
class VerificationConfig:
    fail_fast: bool = True
    commands: List[str] = field(
        default_factory=lambda: ["python -m compileall .", "pytest"]
    )


@dataclass
class LoggingConfig:
    directory: str = ".sentinelbox/logs"
    max_file_size_mb: int = 50
    backup_count: int = 10


@dataclass
class PolicyConfig:
    default_action: str = "deny"
    allowed_commands: List[str] = field(
        default_factory=lambda: [
            "python",
            "python3",
            "pytest",
            "ruff",
            "mypy",
            "npm",
            "node",
            "git",
            "cargo",
            "go",
        ]
    )
    denied_commands: List[str] = field(
        default_factory=lambda: [
            "shutdown",
            "reboot",
            "format",
            "diskpart",
            "mkfs",
            "sudo",
            "chown",
        ]
    )


@dataclass
class SentinelConfig:
    mode: str = "isolated"
    preserve_git: bool = True
    hash_mode: HashMode = HashMode.BALANCED
    network_mode: NetworkMode = NetworkMode.DENY
    ignore_patterns: List[str] = field(
        default_factory=lambda: [
            ".git/objects",
            ".git/logs",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            "node_modules",
            ".venv",
            "venv",
            "dist",
            "build",
            ".sentinelbox",
        ]
    )
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    verification: VerificationConfig = field(default_factory=VerificationConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> SentinelConfig:
        if not config_path or not config_path.exists():
            return cls()

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data: Dict[str, Any] = yaml.safe_load(f) or {}
        except Exception as e:
            raise PolicyError(f"Failed to parse config file at {config_path}: {e}") from e

        cfg = cls()
        if "sandbox" in data:
            sb = data["sandbox"]
            cfg.mode = sb.get("mode", cfg.mode)
            cfg.preserve_git = sb.get("preserve_git", cfg.preserve_git)
            if "hash_mode" in sb:
                cfg.hash_mode = HashMode(sb["hash_mode"].upper())

        if "ignore_patterns" in data and isinstance(data["ignore_patterns"], list):
            cfg.ignore_patterns = data["ignore_patterns"]

        if "network" in data:
            net = data["network"]
            mode_str = net.get("mode", "deny").lower()
            cfg.network_mode = NetworkMode(mode_str)

        if "execution" in data:
            ex = data["execution"]
            cfg.execution.timeout_seconds = float(
                ex.get("timeout_seconds", cfg.execution.timeout_seconds)
            )
            cfg.execution.max_output_bytes = int(
                ex.get("max_output_bytes", cfg.execution.max_output_bytes)
            )
            if "shell" in ex:
                cfg.execution.shell = ShellType(ex["shell"].lower())

        if "verification" in data:
            vf = data["verification"]
            cfg.verification.fail_fast = vf.get("fail_fast", cfg.verification.fail_fast)
            if "commands" in vf and isinstance(vf["commands"], list):
                cfg.verification.commands = vf["commands"]

        if "policy" in data:
            pc = data["policy"]
            cfg.policy.default_action = pc.get("default_action", cfg.policy.default_action)
            if "allowed_commands" in pc and isinstance(pc["allowed_commands"], list):
                cfg.policy.allowed_commands = pc["allowed_commands"]
            if "denied_commands" in pc and isinstance(pc["denied_commands"], list):
                cfg.policy.denied_commands = pc["denied_commands"]

        if "logging" in data:
            lg = data["logging"]
            cfg.logging.directory = lg.get("directory", cfg.logging.directory)
            cfg.logging.max_file_size_mb = lg.get(
                "max_file_size_mb", cfg.logging.max_file_size_mb
            )
            cfg.logging.backup_count = lg.get("backup_count", cfg.logging.backup_count)

        return cfg