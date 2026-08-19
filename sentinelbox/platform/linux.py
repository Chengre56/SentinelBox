from __future__ import annotations

import os
import signal
import psutil
from typing import Set


class LinuxPlatformAdapter:
    def kill_process_tree(self, pid: int) -> None:
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.send_signal(signal.SIGTERM)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            parent.send_signal(signal.SIGTERM)

            _, alive = psutil.wait_procs(children + [parent], timeout=3.0)
            for p in alive:
                try:
                    p.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except Exception:
                pass

    def get_supported_security_features(self) -> Set[str]:
        return {
            "posix_permissions",
            "process_groups",
            "file_descriptors",
            "resource_limits_rlimit",
            "unshare_namespaces_capable",
        }

    def validate_path_safety(self, path: str) -> bool:
        return "\x00" not in path