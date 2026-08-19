from __future__ import annotations

import difflib
from pathlib import Path
from typing import List, Optional

from sentinelbox.models import DiffReport, FileChange, FileChangeType, Snapshot


def is_binary_string(bytes_data: bytes) -> bool:
    """Determines if a byte buffer represents binary content."""
    textchars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
    return bool(bytes_data.translate(None, textchars))


def generate_unified_diff(
    old_path: Optional[Path], new_path: Optional[Path], rel_name: str
) -> Optional[str]:
    """Produces unified diff string for text files; returns notice for binaries."""
    old_lines: List[str] = []
    new_lines: List[str] = []

    if old_path and old_path.exists() and old_path.is_file():
        try:
            old_bytes = old_path.read_bytes()
            if is_binary_string(old_bytes[:4096]):
                return f"Binary file {rel_name} changed"
            old_lines = old_bytes.decode("utf-8", errors="replace").splitlines(keepends=True)
        except Exception:
            return None

    if new_path and new_path.exists() and new_path.is_file():
        try:
            new_bytes = new_path.read_bytes()
            if is_binary_string(new_bytes[:4096]):
                return f"Binary file {rel_name} changed"
            new_lines = new_bytes.decode("utf-8", errors="replace").splitlines(keepends=True)
        except Exception:
            return None

    diff = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=f"a/{rel_name}" if old_path else "/dev/null",
            tofile=f"b/{rel_name}" if new_path else "/dev/null",
        )
    )
    return "".join(diff) if diff else None


class DiffEngine:
    """Calculates granular diffs between snapshots and disk representations."""

    @staticmethod
    def compare_snapshots(before: Snapshot, after: Snapshot) -> DiffReport:
        changes: List[FileChange] = []
        before_keys = set(before.files.keys())
        after_keys = set(after.files.keys())

        # Created files
        created = after_keys - before_keys
        for k in sorted(created):
            rec = after.files[k]
            new_p = Path(after.root_path) / k
            patch = generate_unified_diff(None, new_p, k) if rec.file_type == "file" else None
            changes.append(FileChange(relative_path=k, change_type=FileChangeType.CREATED, new_record=rec, diff_patch=patch))

        # Deleted files
        deleted = before_keys - after_keys
        for k in sorted(deleted):
            rec = before.files[k]
            old_p = Path(before.root_path) / k
            patch = generate_unified_diff(old_p, None, k) if rec.file_type == "file" else None
            changes.append(FileChange(relative_path=k, change_type=FileChangeType.DELETED, old_record=rec, diff_patch=patch))

        # Modified files
        common = before_keys & after_keys
        for k in sorted(common):
            b_rec = before.files[k]
            a_rec = after.files[k]
            if b_rec.sha256 != a_rec.sha256 or b_rec.target != a_rec.target:
                old_p = Path(before.root_path) / k
                new_p = Path(after.root_path) / k
                patch = generate_unified_diff(old_p, new_p, k) if a_rec.file_type == "file" else None
                changes.append(
                    FileChange(
                        relative_path=k,
                        change_type=FileChangeType.MODIFIED,
                        old_record=b_rec,
                        new_record=a_rec,
                        diff_patch=patch,
                    )
                )
            elif b_rec.mode != a_rec.mode:
                changes.append(
                    FileChange(
                        relative_path=k,
                        change_type=FileChangeType.PERMISSION_CHANGED,
                        old_record=b_rec,
                        new_record=a_rec,
                    )
                )

        n_created = sum(1 for c in changes if c.change_type == FileChangeType.CREATED)
        n_modified = sum(1 for c in changes if c.change_type in (FileChangeType.MODIFIED, FileChangeType.PERMISSION_CHANGED))
        n_deleted = sum(1 for c in changes if c.change_type == FileChangeType.DELETED)

        return DiffReport(changes=changes, total_created=n_created, total_modified=n_modified, total_deleted=n_deleted)