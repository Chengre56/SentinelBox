from pathlib import Path
from sentinelbox.hashing import canonical_json_digest
from sentinelbox.models import HashMode
from sentinelbox.snapshot import SnapshotEngine


def test_deterministic_snapshot_digest(tmp_path: Path) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text("print('hello world')", encoding="utf-8")

    sub_dir = tmp_path / "pkg"
    sub_dir.mkdir()
    (sub_dir / "mod.py").write_text("x = 42", encoding="utf-8")

    engine = SnapshotEngine(mode=HashMode.STRICT)
    snap1 = engine.create_snapshot(tmp_path)
    snap2 = engine.create_snapshot(tmp_path)

    # Hashes must be identical for unchanged directory state
    assert snap1.state_digest == snap2.state_digest
    assert len(snap1.files) == 2


def test_snapshot_detects_changes(tmp_path: Path) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text("v1", encoding="utf-8")

    engine = SnapshotEngine(mode=HashMode.STRICT)
    snap1 = engine.create_snapshot(tmp_path)

    app_file.write_text("v2", encoding="utf-8")
    snap2 = engine.create_snapshot(tmp_path)

    assert snap1.state_digest != snap2.state_digest