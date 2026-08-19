from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class SecurityLevel(str, Enum):
    LEVEL_0_ADVISORY = "ADVISORY"
    LEVEL_1_WORKSPACE_ISOLATION = "WORKSPACE_ISOLATED"
    LEVEL_2_RESTRICTED_EXECUTION = "RESTRICTED_EXECUTION"
    LEVEL_3_OS_SANDBOX = "OS_SANDBOX"
    LEVEL_4_CONTAINER = "CONTAINER"


class TransactionStatus(str, Enum):
    CREATED = "CREATED"
    PREPARING = "PREPARING"
    RUNNING = "RUNNING"
    VERIFYING = "VERIFYING"
    COMMITTING = "COMMITTING"
    COMMITTED = "COMMITTED"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class GuardAction(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    CONFIRM = "CONFIRM"


class GuardSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FileChangeType(str, Enum):
    CREATED = "CREATED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    PERMISSION_CHANGED = "PERMISSION_CHANGED"


class VerificationStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class HashMode(str, Enum):
    FAST = "FAST"
    BALANCED = "BALANCED"
    STRICT = "STRICT"


class ShellType(str, Enum):
    AUTO = "auto"
    POSIX = "posix"
    BASH = "bash"
    ZSH = "zsh"
    POWERSHELL = "powershell"
    CMD = "cmd"
    DIRECT = "direct"


class NetworkMode(str, Enum):
    DENY = "deny"
    ALLOW = "allow"
    ALLOWLIST = "allowlist"
    INHERIT = "inherit"


@dataclass(frozen=True)
class FileRecord:
    relative_path: str
    file_type: str  # "file", "dir", "symlink"
    size: int
    mtime: float
    mode: int
    sha256: Optional[str] = None
    target: Optional[str] = None  # Symlink destination

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "file_type": self.file_type,
            "size": self.size,
            "mtime": self.mtime,
            "mode": self.mode,
            "sha256": self.sha256,
            "target": self.target,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FileRecord:
        return cls(
            relative_path=data["relative_path"],
            file_type=data["file_type"],
            size=data["size"],
            mtime=data["mtime"],
            mode=data["mode"],
            sha256=data.get("sha256"),
            target=data.get("target"),
        )


@dataclass(frozen=True)
class Snapshot:
    root_path: str
    created_at: str
    state_digest: str
    mode: HashMode
    files: Dict[str, FileRecord]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_path": self.root_path,
            "created_at": self.created_at,
            "state_digest": self.state_digest,
            "mode": self.mode.value,
            "files": {k: v.to_dict() for k, v in sorted(self.files.items())},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Snapshot:
        return cls(
            root_path=data["root_path"],
            created_at=data["created_at"],
            state_digest=data["state_digest"],
            mode=HashMode(data["mode"]),
            files={k: FileRecord.from_dict(v) for k, v in data.get("files", {}).items()},
        )


@dataclass(frozen=True)
class FileChange:
    relative_path: str
    change_type: FileChangeType
    old_record: Optional[FileRecord] = None
    new_record: Optional[FileRecord] = None
    diff_patch: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "change_type": self.change_type.value,
            "old_record": self.old_record.to_dict() if self.old_record else None,
            "new_record": self.new_record.to_dict() if self.new_record else None,
            "diff_patch": self.diff_patch,
        }


@dataclass(frozen=True)
class DiffReport:
    changes: List[FileChange]
    total_created: int
    total_modified: int
    total_deleted: int

    @property
    def has_changes(self) -> bool:
        return len(self.changes) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_created": self.total_created,
            "total_modified": self.total_modified,
            "total_deleted": self.total_deleted,
            "changes": [c.to_dict() for c in self.changes],
        }


@dataclass(frozen=True)
class CommandRequest:
    command: List[str] | str
    cwd: Optional[Path] = None
    env: Dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 120.0
    shell: ShellType = ShellType.DIRECT


@dataclass(frozen=True)
class GuardDecision:
    action: GuardAction
    rule_id: str
    reason: str
    severity: GuardSeverity = GuardSeverity.INFO
    matched_pattern: Optional[str] = None
    normalized_command: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "severity": self.severity.value,
            "matched_pattern": self.matched_pattern,
            "normalized_command": self.normalized_command,
        }


@dataclass(frozen=True)
class CommandResult:
    command: List[str] | str
    exit_code: int
    duration_seconds: float
    stdout: str
    stderr: str
    timed_out: bool = False
    output_truncated: bool = False
    resource_limit_hit: bool = False

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.resource_limit_hit

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "output_truncated": self.output_truncated,
            "resource_limit_hit": self.resource_limit_hit,
            "success": self.success,
        }


@dataclass(frozen=True)
class VerificationStepResult:
    command: str
    status: VerificationStatus
    exit_code: int
    duration_seconds: float
    stdout: str
    stderr: str
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "message": self.message,
        }


@dataclass(frozen=True)
class VerificationReport:
    passed: bool
    results: List[VerificationStepResult] = field(default_factory=list)
    duration_seconds: float = 0.0
    failure_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "duration_seconds": self.duration_seconds,
            "failure_reason": self.failure_reason,
            "results": [r.to_dict() for r in self.results],
        }


@dataclass(frozen=True)
class CommitResult:
    success: bool
    transaction_id: str
    initial_digest: str
    committed_digest: str
    changes_applied: int
    duration_seconds: float
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "transaction_id": self.transaction_id,
            "initial_digest": self.initial_digest,
            "committed_digest": self.committed_digest,
            "changes_applied": self.changes_applied,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    transaction_id: str
    event: str
    details: Dict[str, Any]

    @classmethod
    def create(cls, transaction_id: str, event: str, details: Dict[str, Any]) -> AuditEvent:
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            transaction_id=transaction_id,
            event=event,
            details=details,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "transaction_id": self.transaction_id,
            "event": self.event,
            **self.details,
        }