import sys
from pathlib import Path
from sentinelbox.config import SentinelConfig, VerificationConfig
from sentinelbox.sandbox import SentinelBox


def test_end_to_end_agent_workflow(tmp_path: Path) -> None:
    # 1. Prepare initial project
    (tmp_path / "math_lib.py").write_text("def multiply(x, y): return x * y\n", encoding="utf-8")
    (tmp_path / "test_math.py").write_text(
        "import math_lib\ndef test_multiply(): assert math_lib.multiply(2, 3) == 6\n",
        encoding="utf-8",
    )

    cfg = SentinelConfig()
    cfg.verification = VerificationConfig(commands=[f"{sys.executable} -m compileall ."])

    # 2. Agent creates new functionality safely
    with SentinelBox.open(tmp_path) as box:
        box.transaction.config = cfg

        # Agent writes new function
        box.write_file(
            "math_lib.py",
            "def multiply(x, y): return x * y\ndef divide(x, y): return x / y if y != 0 else 0\n",
        )

        diff = box.diff()
        assert diff.has_changes
        assert diff.total_modified == 1

        ver = box.verify()
        assert ver.passed

        res = box.commit()
        assert res.success

    # 3. Assert live workspace has updated state
    content = (tmp_path / "math_lib.py").read_text(encoding="utf-8")
    assert "def divide" in content