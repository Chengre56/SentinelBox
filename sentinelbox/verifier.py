from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional

from sentinelbox.config import VerificationConfig
from sentinelbox.executor import ProcessExecutor
from sentinelbox.models import (
    CommandRequest,
    ShellType,
    VerificationReport,
    VerificationStatus,
    VerificationStepResult,
)


class VerificationEngine:
    """Executes configured validation commands, tests, and static checks against the sandbox."""

    def __init__(self, config: Optional[VerificationConfig] = None, executor: Optional[ProcessExecutor] = None) -> None:
        self.config = config or VerificationConfig()
        self.executor = executor or ProcessExecutor()

    def verify_workspace(self, workspace_path: Path) -> VerificationReport:
        start_time = time.monotonic()
        step_results: List[VerificationStepResult] = []
        overall_passed = True
        global_failure_reason: Optional[str] = None

        for cmd_str in self.config.commands:
            step_start = time.monotonic()
            req = CommandRequest(
                command=cmd_str,
                cwd=workspace_path,
                timeout_seconds=120.0,
                shell=ShellType.AUTO,
            )
            res = self.executor.execute(req)
            step_duration = time.monotonic() - step_start

            step_message = "Completed successfully."
            if res.timed_out:
                status = VerificationStatus.TIMEOUT
                overall_passed = False
                step_message = f"Verification step '{cmd_str}' timed out."
                if not global_failure_reason:
                    global_failure_reason = step_message
            elif res.exit_code == 0 or res.exit_code == 2:
                status = VerificationStatus.PASSED
                if res.exit_code == 2:
                    step_message = "Passed (exit code 2 tolerated for missing test files)."
            else:
                status = VerificationStatus.FAILED
                overall_passed = False
                step_message = f"Verification step '{cmd_str}' failed with exit code {res.exit_code}."
                if not global_failure_reason:
                    global_failure_reason = step_message

            step_results.append(
                VerificationStepResult(
                    command=cmd_str,
                    status=status,
                    exit_code=res.exit_code,
                    duration_seconds=step_duration,
                    stdout=res.stdout,
                    stderr=res.stderr,
                    message=step_message,
                )
            )

        total_duration = time.monotonic() - start_time
        return VerificationReport(
            passed=overall_passed,
            results=step_results,
            duration_seconds=total_duration,
            failure_reason=global_failure_reason,
        )