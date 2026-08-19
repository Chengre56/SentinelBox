from __future__ import annotations

import fnmatch
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Dict, List, Optional, Set

from sentinelbox.exceptions import SnapshotError
from sentinelbox.hashing import compute_tree_digest, hash_file_stream
from sentinelbox.models import FileRecord, HashMode, Snapshot


class SnapshotEngine:
    """Creates deterministic, canonical state snapshots of directory trees."""

    def __init__(self, ignore_patterns: Optional[List[str]] = None, mode: HashMode = HashMode.BALANCED) -> None:
        self.ignore_patterns = ignore_patterns or [
            ".git/objects",
            ".git/logs",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            "node_modules",
            ".venv",
            "venv",
            "dist",
            "build",
            ".sentinelbox",
        ]
        self.mode = mode

    def _should_ignore(self, rel_path: str) -> bool:
        normalized = rel_path.replace("\\", "/")
        for pat in self.ignore_patterns:
            pat_norm = pat.replace("\\", "/").rstrip("/")
            if fnmatch.fnmatch(normalized, pat_norm) or fnmatch.fnmatch(normalized, f"{pat_norm}/*") or normalized.startswith(f"{pat_norm}/"):
                return True
        return False

    def create_snapshot(self, root_dir: Path) -> Snapshot:
        resolved_root = root_dir.resolve()
        if not resolved_root.exists() or not resolved_root.is_dir():
            raise SnapshotError(f"Cannot snapshot non-existent or invalid directory: {resolved_root}")

        records: Dict[str, FileRecord] = {}
        digest_entries: List[tuple[str, str]] = []

        try:
            for root, dirs, files in os.walk(resolved_root, topdown=True, followlinks=False):
                rel_root = os.path.relpath(root, resolved_root)
                if rel_root == ".":
                    rel_root = ""

                # Prune ignored directories
                dirs[:] = [
                    d for d in dirs
                    if not self._should_ignore(os.path.join(rel_root, d) if rel_root else d)
                ]

                # Process files
                for f in files:
                    rel_path = os.path.normpath(os.path.join(rel_root, f)).replace("\\", "/")
                    if self._should_ignore(rel_path):
                        continue

                    full_path = Path(root) / f
                    try:
                        stat = full_path.lstat()
                        is_symlink = full_path.is_symlink()
                        file_type = "symlink" if is_symlink else ("dir" if full_path.is_dir() else "file")
                        target = str(os.readlink(full_path)) if is_symlink else None

                        file_hash: Optional[str] = None
                        if file_type == "file":
                            if self.mode == HashMode.STRICT or (self.mode == HashMode.BALANCED and stat.st_size <= 50 * 1024 * 1024):
                                file_hash = hash_file_stream(full_path)
                            else:
                                file_hash = f"fast:{stat.st_size}:{stat.st_mtime_ns}"
                        elif file_type == "symlink":
                            file_hash = f"symlink:{target}"
                        else:
                            file_hash = "dir"

                        record = FileRecord(
                            relative_path=rel_path,
                            file_type=file_type,
                            size=stat.st_size,
                            mtime=stat.st_mtime,
                            mode=stat.st_mode,
                            sha256=file_hash,
                            target=target,
                        )
                        records[rel_path] = record
                        digest_entries.append((rel_path, file_hash or ""))
                    except (PermissionError, FileNotFoundError):
                        continue
        except Exception as e:
            raise SnapshotError(f"Snapshot generation failed on {resolved_root}: {e}") from e
        state_digest = compute_tree_digest(resolved_root)
        return Snapshot(
            root_path=str(resolved_root),
            created_at=datetime.now(timezone.utc).isoformat(),
            state_digest=state_digest,
            mode=self.mode,
            files=records,
        )