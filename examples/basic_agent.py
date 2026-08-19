"""
Example showing an AI Coding Agent using SentinelBox to safely apply validated code changes.
"""

from pathlib import Path
from sentinelbox import SentinelBox, SentinelConfig


def run_agent_task(project_dir: Path) -> None:
    print(f"[*] Agent beginning work on project: {project_dir}")

    with SentinelBox.open(project_dir) as sandbox:
        print(f"[*] Sandbox active (Security Level: {sandbox.security_level.value})")

        # 1. Modify project code in sandbox
        sandbox.write_file(
            "src/utils.py",
            "def compute_hash(data: str) -> str:\n    import hashlib\n    return hashlib.sha256(data.encode()).hexdigest()\n",
        )

        # 2. Inspect diff before executing validation
        diff = sandbox.diff()
        print(f"[*] Diff generated: {len(diff.changes)} changes pending.")

        # 3. Verify workspace through automated checks
        verification = sandbox.verify()
        if not verification.passed:
            print(f"[!] Verification failed: {verification.failure_reason}. Rolling back.")
            sandbox.rollback()
            return

        # 4. Atomically commit changes to live workspace
        result = sandbox.commit()
        print(f"[✓] Successfully committed transaction: {result.transaction_id}")


if __name__ == "__main__":
    work_dir = Path("./example_project")
    work_dir.mkdir(exist_ok=True)
    (work_dir / "src").mkdir(exist_ok=True)
    run_agent_task(work_dir)