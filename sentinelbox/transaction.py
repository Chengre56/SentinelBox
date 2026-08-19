from __future__ import annotations

import json
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from sentinelbox.config import SentinelConfig
from sentinelbox.diff import DiffEngine
from sentinelbox.exceptions import (
    CommitError,
    GuardViolation,
    PathSecurityError,
    RollbackError,
    SnapshotError,
    TransactionConflict,
    VerificationError,
)
from sentinelbox.executor import ProcessExecutor
from sentinelbox.guard import CommandGuard
from sentinelbox.logger import AuditLogger
from sentinelbox.models import (
    CommandRequest,
    CommandResult,
    CommitResult,
    DiffReport,
    FileChangeType,
    GuardAction,
    SecurityLevel,
    Snapshot,
    TransactionStatus,
    VerificationReport,
)
from sentinelbox.snapshot import SnapshotEngine
from sentinelbox.verifier import VerificationEngine


class TransactionJournal:
    """Maintains an append-only journal for atomic operations and crash recovery."""

    def __init__(self, journal_path: Path) -> None:
        self.journal_path = journal_path

    def append(self, phase: str, status: TransactionStatus, metadata: Optional[Dict[str, Any]] = None) -> None:
        # Ensure the parent directory (and transaction folder) always exists before writing
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        
        entry = {
            "timestamp": time.time(),
            "phase": phase,
            "status": status.value,
            "metadata": metadata or {},
        }
        with open(self.journal_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")


class WorkspaceTransaction:
    """Manages transactional lifecycle: clone, isolate, verify, atomic apply, rollback."""

    def __init__(
        self,
        source_workspace: Path,
        config: Optional[SentinelConfig] = None,
        transaction_id: Optional[str] = None,
    ) -> None:
        self.source_workspace = source_workspace.resolve()
        self.config = config or SentinelConfig()
        self.transaction_id = transaction_id or uuid.uuid4().hex[:12]
        self.status = TransactionStatus.CREATED

        self.sentinel_dir = self.source_workspace / ".sentinelbox"
        self.tx_dir = self.sentinel_dir / "transactions" / self.transaction_id
        self.sandbox_workspace = self.tx_dir / "workspace"
        self.journal = TransactionJournal(self.tx_dir / "journal.jsonl")

        self.logger = AuditLogger(self.sentinel_dir / "logs")
        self.snapshot_engine = SnapshotEngine(
            ignore_patterns=self.config.ignore_patterns, mode=self.config.hash_mode
        )
        self.guard = CommandGuard()
        self.executor = ProcessExecutor(self.config.execution)
        self.verifier = VerificationEngine(self.config.verification, self.executor)

        self.initial_snapshot: Optional[Snapshot] = None
        self.pre_commit_snapshot: Optional[Snapshot] = None
        self.last_diff_report: Optional[DiffReport] = None

    def begin(self) -> None:
        """Initializes the isolated sandbox environment."""
        self.status = TransactionStatus.PREPARING
        self.journal.append("begin", self.status)
        self.logger.log_event(
            self.transaction_id,
            "TRANSACTION_CREATED",
            {
                "source": str(self.source_workspace),
                "security_level": SecurityLevel.LEVEL_1_WORKSPACE_ISOLATION.value,
            },
        )

        # 1. Take initial state snapshot of protected workspace
        self.initial_snapshot = self.snapshot_engine.create_snapshot(self.source_workspace)

        # 2. Copy workspace to isolated transaction directory
        if self.tx_dir.exists():
            shutil.rmtree(self.tx_dir)
        self.sandbox_workspace.mkdir(parents=True, exist_ok=True)

        def ignore_filter(src: str, names: list[str]) -> set[str]:
            ignored = set()
            rel_src = os.path.relpath(src, self.source_workspace)
            for name in names:
                rel_path = os.path.normpath(os.path.join(rel_src if rel_src != "." else "", name))
                if name == ".sentinelbox" or any(pat in rel_path for pat in [".venv", "node_modules"]):
                    ignored.add(name)
            return ignored

        shutil.copytree(self.source_workspace, self.sandbox_workspace, dirs_exist_ok=True, ignore=ignore_filter)

        self.status = TransactionStatus.RUNNING
        self.journal.append("initialized", self.status, {"initial_digest": self.initial_snapshot.state_digest})
        self.logger.log_event(self.transaction_id, "SANDBOX_CREATED", {"sandbox": str(self.sandbox_workspace)})

    def execute(self, command: List[str] | str, timeout: Optional[float] = None) -> CommandResult:
        """Executes a command safely inside the isolated transaction workspace."""
        if self.status != TransactionStatus.RUNNING:
            raise GuardViolation(f"Cannot execute in transaction status: {self.status.value}")

        req = CommandRequest(
            command=command,
            cwd=self.sandbox_workspace,
            timeout_seconds=timeout or self.config.execution.timeout_seconds,
            shell=self.config.execution.shell,
        )

        decision = self.guard.inspect_command(req)
        self.logger.log_event(self.transaction_id, "COMMAND_INSPECTED", decision.to_dict())

        if decision.action == GuardAction.DENY:
            self.logger.log_event(self.transaction_id, "COMMAND_DENIED", decision.to_dict())
            raise GuardViolation(f"Command denied by rule {decision.rule_id}: {decision.reason}")

        self.logger.log_event(
            self.transaction_id,
            "COMMAND_STARTED",
            {"command": req.command, "normalized": decision.normalized_command},
        )
        result = self.executor.execute(req)

        self.logger.log_event(
            self.transaction_id,
            "COMMAND_FINISHED",
            {
                "command": req.command,
                "exit_code": result.exit_code,
                "duration_seconds": result.duration_seconds,
                "timed_out": result.timed_out,
            },
        )
        return result

    def write_file(self, relative_path: str, content: str | bytes) -> None:
        """Safely writes a file within the sandbox root."""
        target = self.guard.validate_path_within_root(relative_path, self.sandbox_workspace)
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            target.write_text(content, encoding="utf-8")
        else:
            target.write_bytes(content)

    def read_file(self, relative_path: str) -> str:
        """Safely reads a file from the sandbox root."""
        target = self.guard.validate_path_within_root(relative_path, self.sandbox_workspace)
        if not target.exists():
            raise FileNotFoundError(f"File not found: {relative_path}")
        return target.read_text(encoding="utf-8")

    def diff(self) -> DiffReport:
        """Computes deterministic diff between initial state and sandbox state."""
        if not self.initial_snapshot:
            raise SnapshotError("Initial snapshot missing.")
        current_sandbox_snapshot = self.snapshot_engine.create_snapshot(self.sandbox_workspace)
        report = DiffEngine.compare_snapshots(self.initial_snapshot, current_sandbox_snapshot)
        self.last_diff_report = report
        return report

    def verify(self) -> VerificationReport:
        """Runs the verification suite against the sandbox workspace."""
        self.status = TransactionStatus.VERIFYING
        self.journal.append("verify_started", self.status)
        self.logger.log_event(self.transaction_id, "VERIFICATION_STARTED", {})

        report = self.verifier.verify_workspace(self.sandbox_workspace)

        if report.passed:
            self.status = TransactionStatus.RUNNING
            self.journal.append("verify_passed", self.status)
            self.logger.log_event(self.transaction_id, "VERIFICATION_PASSED", report.to_dict())
        else:
            self.status = TransactionStatus.FAILED
            self.journal.append("verify_failed", self.status, {"reason": report.failure_reason})
            self.logger.log_event(self.transaction_id, "VERIFICATION_FAILED", report.to_dict())

        return report

    def commit(self) -> CommitResult:
        """
        Atomically commits verified changes to the live workspace.
        Fails and aborts if external concurrent modifications are detected.
        """
        start_time = time.monotonic()
        if not self.initial_snapshot:
            raise CommitError("Transaction cannot commit without an initial snapshot.")

        self.status = TransactionStatus.COMMITTING
        self.journal.append("commit_started", self.status)
        self.logger.log_event(self.transaction_id, "COMMIT_STARTED", {})

        # 1. External change detection: verify live workspace matches initial state
        current_live_snapshot = self.snapshot_engine.create_snapshot(self.source_workspace)
        if current_live_snapshot.state_digest != self.initial_snapshot.state_digest:
            self.status = TransactionStatus.ABORTED
            self.journal.append(
                "conflict_aborted",
                self.status,
                {
                    "expected_digest": self.initial_snapshot.state_digest,
                    "actual_digest": current_live_snapshot.state_digest,
                },
            )
            self.logger.log_event(
                self.transaction_id,
                "COMMIT_ABORTED",
                {"reason": "External workspace modification detected."},
            )
            raise TransactionConflict(
                f"Transaction commit aborted: Live workspace modified externally. "
                f"Expected state: {self.initial_snapshot.state_digest[:8]}, Current state: {current_live_snapshot.state_digest[:8]}."
            )

        # 2. Calculate final diff from sandbox
        sandbox_snapshot = self.snapshot_engine.create_snapshot(self.sandbox_workspace)
        diff_report = DiffEngine.compare_snapshots(self.initial_snapshot, sandbox_snapshot)

        # 3. Apply changes atomically
        applied_count = 0
        try:
            for change in diff_report.changes:
                target_path = self.guard.validate_path_within_root(
                    change.relative_path, self.source_workspace
                )
                source_sandbox_path = self.guard.validate_path_within_root(
                    change.relative_path, self.sandbox_workspace
                )

                if change.change_type in (FileChangeType.CREATED, FileChangeType.MODIFIED):
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    if source_sandbox_path.is_symlink():
                        if target_path.exists() or target_path.is_symlink():
                            target_path.unlink()
                        os.symlink(os.readlink(source_sandbox_path), target_path)
                    else:
                        shutil.copy2(source_sandbox_path, target_path)
                    applied_count += 1

                elif change.change_type == FileChangeType.DELETED:
                    if target_path.exists() or target_path.is_symlink():
                        if target_path.is_dir() and not target_path.is_symlink():
                            shutil.rmtree(target_path)
                        else:
                            target_path.unlink()
                        applied_count += 1

            # 4. Confirm final live workspace integrity
            final_live_snapshot = self.snapshot_engine.create_snapshot(self.source_workspace)
            self.status = TransactionStatus.COMMITTED
            self.journal.append(
                "commit_completed",
                self.status,
                {"final_digest": final_live_snapshot.state_digest, "applied": applied_count},
            )
            self.logger.log_event(
                self.transaction_id,
                "COMMIT_COMPLETED",
                {"final_digest": final_live_snapshot.state_digest, "applied": applied_count},
            )

            # Cleanup transaction workspace
            self._cleanup()

            return CommitResult(
                success=True,
                transaction_id=self.transaction_id,
                initial_digest=self.initial_snapshot.state_digest,
                committed_digest=final_live_snapshot.state_digest,
                changes_applied=applied_count,
                duration_seconds=time.monotonic() - start_time,
            )

        except Exception as e:
            self.status = TransactionStatus.FAILED
            self.journal.append("commit_failed", self.status, {"error": str(e)})
            self.logger.log_event(self.transaction_id, "COMMIT_FAILED", {"error": str(e)})
            raise CommitError(f"Commit operation failed during application: {e}") from e

    def rollback(self) -> None:
        """Discards transaction changes. Live workspace remains completely unmodified."""
        self.status = TransactionStatus.ROLLING_BACK
        self.journal.append("rollback_started", self.status)
        self.logger.log_event(self.transaction_id, "ROLLBACK_STARTED", {})

        self._cleanup()

        self.status = TransactionStatus.ROLLED_BACK
        self.journal.append("rollback_completed", self.status)
        self.logger.log_event(self.transaction_id, "ROLLBACK_COMPLETED", {})

    def _cleanup(self) -> None:
        if self.tx_dir.exists():
            try:
                shutil.rmtree(self.tx_dir)
            except Exception:
                pass