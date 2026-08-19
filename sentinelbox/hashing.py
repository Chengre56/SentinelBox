import hashlib
import os
from pathlib import Path

def hash_file_stream(filepath, chunk_size=8192):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()

def compute_tree_digest(root_dir):
    sha256 = hashlib.sha256()
    root_path = Path(root_dir)
    for path in sorted(root_path.rglob("*")):
        if path.is_file() and ".sentinelbox" not in path.parts:
            rel_path = str(path.relative_to(root_path))
            sha256.update(rel_path.encode("utf-8"))
            sha256.update(hash_file_stream(path).encode("utf-8"))
    return sha256.hexdigest()
