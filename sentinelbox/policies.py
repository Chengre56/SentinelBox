from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from sentinelbox.models import CommandRequest, GuardAction, GuardDecision, GuardSeverity


@dataclass
class PolicyRule:
    rule_id: str
    description: str
    action: GuardAction
    severity: GuardSeverity
    pattern: Optional[re.Pattern[str]] = None
    subcommands: List[str] = field(default_factory=list)


class PolicyEngine:
    """Evaluates commands and operations against layered security rules."""

    def __init__(
        self,
        default_action: GuardAction = GuardAction.DENY,
        allowed_executables: Optional[List[str]] = None,
        denied_executables: Optional[List[str]] = None,
        custom_rules: Optional[List[PolicyRule]] = None,
    ) -> None:
        self.default_action = default_action
        self.allowed_executables = set(
            allowed_executables
            or [
                "python",
                "python3",
                "pytest",
                "ruff",
                "mypy",
                "black",
                "flake8",
                "npm",
                "npx",
                "node",
                "git",
                "cargo",
                "go",
                "rustc",
                "make",
                "cat",
                "ls",
                "dir",
                "echo",
                "find",
                "grep",
            ]
        )
        self.denied_executables = set(
            denied_executables
            or [
                "shutdown",
                "reboot",
                "poweroff",
                "format",
                "diskpart",
                "mkfs",
                "fdisk",
                "dd",
                "iptables",
                "ufw",
                "netsh",
                "useradd",
                "userdel",
                "passwd",
                "sudo",
                "su",
                "chmod",
                "chown",
                "curl",
                "wget",
                "nc",
                "ncat",
                "netcat",
            ]
        )
        self.dangerous_patterns: List[PolicyRule] = [
            PolicyRule(
                rule_id="FS-001",
                description="Root filesystem destructive deletion",
                action=GuardAction.DENY,
                severity=GuardSeverity.CRITICAL,
                pattern=re.compile(r"\brm\s+-(?:r|f|rf|fr)\s+(?:/|/\*|~|\$HOME)\b"),
            ),
            PolicyRule(
                rule_id="FS-002",
                description="Windows drive root deletion",
                action=GuardAction.DENY,
                severity=GuardSeverity.CRITICAL,
                pattern=re.compile(r"\b(?:del|rd|rmdir)\s+/[sq]\s+[a-zA-Z]:\\", re.IGNORECASE),
            ),
            PolicyRule(
                rule_id="FS-003",
                description="Raw disk writes",
                action=GuardAction.DENY,
                severity=GuardSeverity.CRITICAL,
                pattern=re.compile(r"\bof=/dev/(?:sd[a-z]|nvme\d+n\d+|hd[a-z])\b"),
            ),
            PolicyRule(
                rule_id="GIT-001",
                description="Destructive hard reset in unapproved context",
                action=GuardAction.DENY,
                severity=GuardSeverity.HIGH,
                pattern=re.compile(r"\bgit\s+reset\s+--hard\b"),
            ),
            PolicyRule(
                rule_id="GIT-002",
                description="Destructive untracked file purge",
                action=GuardAction.DENY,
                severity=GuardSeverity.HIGH,
                pattern=re.compile(r"\bgit\s+clean\s+-(?:[a-zA-Z]*f[a-zA-Z]*d|[a-zA-Z]*d[a-zA-Z]*f)\b"),
            ),
            PolicyRule(
                rule_id="SEC-001",
                description="Credential extraction attempts",
                action=GuardAction.DENY,
                severity=GuardSeverity.HIGH,
                pattern=re.compile(
                    r"\b(?:id_rsa|id_ed25519|\.aws/credentials|\.ssh/authorized_keys|\.netrc|/etc/shadow)\b"
                ),
            ),
        ]
        if custom_rules:
            self.dangerous_patterns.extend(custom_rules)

    def evaluate_command(self, request: CommandRequest) -> GuardDecision:
        """Evaluates command safety deterministically."""
        cmd_str = " ".join(request.command) if isinstance(request.command, list) else request.command
        normalized = cmd_str.strip()

        if not normalized:
            return GuardDecision(
                action=GuardAction.DENY,
                rule_id="CMD-EMPTY",
                reason="Empty command received",
                severity=GuardSeverity.LOW,
                normalized_command=normalized,
            )

        # 1. Match dangerous regex patterns first
        for rule in self.dangerous_patterns:
            if rule.pattern and rule.pattern.search(normalized):
                return GuardDecision(
                    action=rule.action,
                    rule_id=rule.rule_id,
                    reason=rule.description,
                    severity=rule.severity,
                    matched_pattern=rule.pattern.pattern,
                    normalized_command=normalized,
                )

        # 2. Tokenize base executable
        try:
            tokens = (
                request.command
                if isinstance(request.command, list)
                else shlex.split(normalized, posix=True)
            )
        except ValueError:
            # Fallback for Windows quotes or malformed syntax: split by whitespace
            tokens = normalized.split()

        if not tokens:
            return GuardDecision(
                action=GuardAction.DENY,
                rule_id="CMD-PARSE-FAIL",
                reason="Failed to parse executable from command string",
                severity=GuardSeverity.MEDIUM,
                normalized_command=normalized,
            )

        raw_exe = Path(tokens[0]).name.lower()
        # Remove common extensions on Windows
        exe = raw_exe[:-4] if raw_exe.endswith((".exe", ".cmd", ".bat")) else raw_exe

        # 3. Check explicitly denied executables
        if exe in self.denied_executables or raw_exe in self.denied_executables:
            return GuardDecision(
                action=GuardAction.DENY,
                rule_id="EXEC-DENIED",
                reason=f"Executable '{tokens[0]}' is explicitly disallowed by policy",
                severity=GuardSeverity.CRITICAL,
                normalized_command=normalized,
            )

        # 4. Check explicitly allowed executables
        if exe in self.allowed_executables or raw_exe in self.allowed_executables:
            return GuardDecision(
                action=GuardAction.ALLOW,
                rule_id="EXEC-ALLOWED",
                reason=f"Executable '{tokens[0]}' is permitted",
                severity=GuardSeverity.INFO,
                normalized_command=normalized,
            )

        # 5. Default action fallback
        return GuardDecision(
            action=self.default_action,
            rule_id="EXEC-DEFAULT-ACTION",
            reason=f"Executable '{tokens[0]}' not in allowlist; applying default policy ({self.default_action.value})",
            severity=GuardSeverity.MEDIUM,
            normalized_command=normalized,
        )