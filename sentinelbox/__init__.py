from __future__ import annotations

import sys
from typing import Protocol, Set

class PlatformAdapter(Protocol):
    def kill_process_tree(self, pid: int) -> None:
        ...

    def get_supported_security_features(self) -> Set[str]:
        ...

    def validate_path_safety(self, path: str) -> bool:
        ...

def get_platform_adapter() -> PlatformAdapter:
    if sys.platform.startswith("win"):
        from sentinelbox.platform.windows import WindowsPlatformAdapter
        return WindowsPlatformAdapter()
    elif sys.platform.startswith("darwin"):
        from sentinelbox.platform.macos import MacOSPlatformAdapter
        return MacOSPlatformAdapter()
    else:
        from sentinelbox.platform.linux import LinuxPlatformAdapter
        return LinuxPlatformAdapter()