from __future__ import annotations

import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from sentinelbox.config import ExecutionConfig
from sentinelbox.models import CommandRequest, CommandResult, ShellType
from sentinelbox.platform import get_platform_adapter


class ProcessExecutor:
    """Manages process lifecycle, timeouts, output limits, and process-tree termination."""

    def __init__(self, config: Optional[ExecutionConfig] = None) -> None:
        self.config = config or ExecutionConfig()
        self.platform_adapter = get_platform_adapter()

    def execute(self, request: CommandRequest) -> CommandResult:
        cwd = str(request.cwd) if request.cwd else None
        timeout = request.timeout_seconds or self.config.timeout_seconds
        max_bytes = self.config.max_output_bytes

        env = os.environ.copy()
        # Remove potentially leaking sensitive environment variables
        for key in list(env.keys()):
            if any(secret in key.lower() for secret in ("token", "secret", "auth", "passwd")):
                env.pop(key, None)
        env["SENTINELBOX"] = "1"
        env.update(request.env)

        # Force command into a single string to satisfy Windows Popen requirements when shell=True
        if isinstance(request.command, list):
            cmd_args = " ".join(str(c) for c in request.command)
        else:
            cmd_args = str(request.command)

        use_shell = True if sys.platform == "win32" else (request.shell != ShellType.DIRECT)

        start_time = time.monotonic()
        timed_out = False
        resource_limit_hit = False
        stdout_chunks: List[bytes] = []
        stderr_chunks: List[bytes] = []
        truncated = False

        # Create new process group on POSIX to enable full tree termination
        kwargs = {}
        if sys.platform != "win32":
            kwargs["start_new_session"] = True

        proc: Optional[subprocess.Popen[bytes]] = None
        try:
            proc = subprocess.Popen(
                cmd_args,
                cwd=cwd,
                env=env,
                shell=use_shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **kwargs,
            )

            try:
                stdout_data, stderr_data = proc.communicate(timeout=timeout)
                if len(stdout_data) > max_bytes:
                    stdout_data = stdout_data[:max_bytes]
                    truncated = True
                    resource_limit_hit = True
                if len(stderr_data) > max_bytes:
                    stderr_data = stderr_data[:max_bytes]
                    truncated = True
                    resource_limit_hit = True

                stdout_chunks.append(stdout_data)
                stderr_chunks.append(stderr_data)
            except subprocess.TimeoutExpired:
                timed_out = True
                if proc.pid:
                    self.platform_adapter.kill_process_tree(proc.pid)
                stdout_data, stderr_data = proc.communicate()
                stdout_chunks.append(stdout_data or b"")
                stderr_chunks.append(stderr_data or b"")

        except Exception as e:
            return CommandResult(
                command=request.command,
                exit_code=1,
                duration_seconds=time.monotonic() - start_time,
                stdout="",
                stderr=f"Execution initiation error: {str(e)}",
                timed_out=False,
                output_truncated=False,
                resource_limit_hit=False,
            )

        duration = time.monotonic() - start_time
        exit_code = proc.returncode if proc and proc.returncode is not None else (124 if timed_out else 1)

        raw_stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
        raw_stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")

        return CommandResult(
            command=request.command,
            exit_code=exit_code,
            duration_seconds=duration,
            stdout=raw_stdout,
            stderr=raw_stderr,
            timed_out=timed_out,
            output_truncated=truncated,
            resource_limit_hit=resource_limit_hit,
        )