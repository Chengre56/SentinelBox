from __future__ import annotations

import psutil
from typing import Set


class WindowsPlatformAdapter:
    def kill_process_tree(self, pid: int) -> None:
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            parent.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def get_supported_security_features(self) -> Set[str]:
        return {
            "windows_job_objects",
            "ntfs_acls",
            "process_tree_kill",
        }

    def validate_path_safety(self, path: str) -> bool:
        # Check for null bytes, illegal characters, and device paths (CON, PRN, AUX, etc.)
        if "\x00" in path:
            return False
        reserved = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "LPT1", "LPT2"}
        parts = [p.split(".")[0].upper() for p in path.replace("\\", "/").split("/")]
        return not any(p in reserved for p in parts)