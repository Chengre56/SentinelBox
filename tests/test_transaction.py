import sys
from pathlib import Path
import pytest

from sentinelbox.config import SentinelConfig, VerificationConfig
from sentinelbox.exceptions import TransactionConflict
from sentinelbox.transaction import WorkspaceTransaction


def test_transaction_commit_success(tmp_path: Path) -> None:
    src_file = tmp_path / "calc.py"
    src_file.write_text("def add(a, b): return a + b\n", encoding="utf-8")

    cfg = SentinelConfig()
    cfg.verification = VerificationConfig(commands=[f"{sys.executable} -m compileall ."])

    tx = WorkspaceTransaction(tmp_path, config=cfg)
    tx.begin()

    # Agent updates calc.py in sandbox
    tx.write_file("calc.py", "def add(a, b): return a + b\ndef sub(a, b): return a - b\n")

    v_rep = tx.verify()
    assert v_rep.passed

    commit_res = tx.commit()
    assert commit_res.success
    assert "def sub" in src_file.read_text(encoding="utf-8")


def test_transaction_conflict_detected_and_aborted(tmp_path: Path) -> None:
    src_file = tmp_path / "app.py"
    src_file.write_text("original", encoding="utf-8")

    cfg = SentinelConfig()
    cfg.verification = VerificationConfig(commands=[f"{sys.executable} -c 'pass'"])

    tx = WorkspaceTransaction(tmp_path, config=cfg)
    tx.begin()

    # Agent makes change in sandbox
    tx.write_file("app.py", "agent modified")

    # Concurrent external modification in live workspace
    src_file.write_text("concurrent user edit", encoding="utf-8")

    tx.verify()

    with pytest.raises(TransactionConflict):
        tx.commit()

    # Verify live workspace was not overwritten by agent
    assert src_file.read_text(encoding="utf-8") == "concurrent user edit"