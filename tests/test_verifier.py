import sys
from pathlib import Path
from sentinelbox.config import VerificationConfig
from sentinelbox.models import VerificationStatus
from sentinelbox.verifier import VerificationEngine


def test_verifier_pass(tmp_path: Path) -> None:
    (tmp_path / "test_ok.py").write_text("def test_dummy(): assert 1 == 1\n", encoding="utf-8")
    cfg = VerificationConfig(
        commands=[f"{sys.executable} -m compileall ."]
    )
    verifier = VerificationEngine(config=cfg)
    report = verifier.verify_workspace(tmp_path)
    assert report.passed
    assert len(report.steps) == 1
    assert report.steps[0].status == VerificationStatus.PASSED


def test_verifier_fail(tmp_path: Path) -> None:
    # Syntax error file
    (tmp_path / "broken.py").write_text("def invalid syntax :::", encoding="utf-8")
    cfg = VerificationConfig(
        commands=[f"{sys.executable} -m compileall ."]
    )
    verifier = VerificationEngine(config=cfg)
    report = verifier.verify_workspace(tmp_path)
    assert not report.passed
    assert report.steps[0].status == VerificationStatus.FAILED