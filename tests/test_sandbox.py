from pathlib import Path
from sentinelbox.sandbox import SentinelBox


def test_sandbox_context_manager_rollback_on_exception(tmp_path: Path) -> None:
    main_file = tmp_path / "main.py"
    main_file.write_text("initial = True", encoding="utf-8")

    try:
        with SentinelBox.open(tmp_path) as box:
            box.write_file("main.py", "initial = False")
            raise RuntimeError("Agent crashed during execution")
    except RuntimeError:
        pass

    # Protected workspace remains unchanged
    assert main_file.read_text(encoding="utf-8") == "initial = True"