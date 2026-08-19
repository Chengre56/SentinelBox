import sys
from pathlib import Path
from sentinelbox.executor import ProcessExecutor
from sentinelbox.models import CommandRequest, ShellType


def test_executor_successful_run(tmp_path: Path) -> None:
    executor = ProcessExecutor()
    req = CommandRequest(
        command=[sys.executable, "-c", "print('SentinelBox-OK')"],
        cwd=tmp_path,
        shell=ShellType.DIRECT,
    )
    result = executor.execute(req)
    assert result.success
    assert result.exit_code == 0
    assert "SentinelBox-OK" in result.stdout


def test_executor_timeout_kill(tmp_path: Path) -> None:
    executor = ProcessExecutor()
    req = CommandRequest(
        command=[sys.executable, "-c", "import time; time.sleep(10)"],
        cwd=tmp_path,
        timeout_seconds=0.5,
        shell=ShellType.DIRECT,
    )
    result = executor.execute(req)
    assert result.timed_out
    assert not result.success