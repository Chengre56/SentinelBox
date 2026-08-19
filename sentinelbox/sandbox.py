from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from sentinelbox.config import SentinelConfig
from sentinelbox.models import (
    CommandResult,
    CommitResult,
    DiffReport,
    SecurityLevel,
    VerificationReport,
)
from sentinelbox.transaction import WorkspaceTransaction


class SentinelBox:
    """Main entrypoint and Context Manager for Agent Sandboxing & State Verification."""

    def __init__(self, project_path: Path | str = ".", config_path: Optional[Path | str] = None) -> None:
        self.project_path = Path(project_path).resolve()
        cfg_p = Path(config_path) if config_path else (self.project_path / "sentinelbox.yaml")
        self.config = SentinelConfig.load(cfg_p if cfg_p.exists() else None)
        self._tx: Optional[WorkspaceTransaction] = None

    @classmethod
    def open(cls, project_path: Path | str = ".", config_path: Optional[Path | str] = None) -> SentinelBox:
        return cls(project_path, config_path)

    def __enter__(self) -> SentinelBox:
        self._tx = WorkspaceTransaction(self.project_path, self.config)
        self._tx.begin()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if self._tx:
            if exc_type is not None:
                self._tx.rollback()
            elif self._tx.status not in ("COMMITTED", "ROLLED_BACK", "ABORTED"):
                self._tx.rollback()

    @property
    def security_level(self) -> SecurityLevel:
        return SecurityLevel.LEVEL_1_WORKSPACE_ISOLATION

    @property
    def transaction(self) -> WorkspaceTransaction:
        if not self._tx:
            raise RuntimeError("Sandbox transaction is not active.")
        return self._tx

    def execute(self, command: List[str] | str, timeout: Optional[float] = None) -> CommandResult:
        return self.transaction.execute(command, timeout)

    def read_file(self, relative_path: str) -> str:
        return self.transaction.read_file(relative_path)

    def write_file(self, relative_path: str, content: str | bytes) -> None:
        self.transaction.write_file(relative_path, content)

    def diff(self) -> DiffReport:
        return self.transaction.diff()

    def verify(self) -> VerificationReport:
        return self.transaction.verify()

    def commit(self) -> CommitResult:
        return self.transaction.commit()

    def rollback(self) -> None:
        self.transaction.rollback()