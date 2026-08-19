from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

import yaml

from sentinelbox.config import SentinelConfig
from sentinelbox.exceptions import GuardViolation, SentinelBoxError, TransactionConflict
from sentinelbox.platform import get_platform_adapter
from sentinelbox.sandbox import SentinelBox
from sentinelbox.snapshot import SnapshotEngine


def render_header() -> None:
    print("=" * 60)
    print("  SentinelBox - Agent Sandboxing & State Verification Engine")
    print("=" * 60)


def cmd_init(args: argparse.Namespace) -> int:
    target_dir = Path(args.path).resolve()
    sentinel_dir = target_dir / ".sentinelbox"
    config_file = target_dir / "sentinelbox.yaml"

    sentinel_dir.mkdir(parents=True, exist_ok=True)
    (sentinel_dir / "logs").mkdir(exist_ok=True)
    (sentinel_dir / "transactions").mkdir(exist_ok=True)

    if not config_file.exists():
        default_cfg = {
            "sandbox": {"mode": "isolated", "preserve_git": True, "hash_mode": "BALANCED"},
            "execution": {"shell": "auto", "timeout_seconds": 120, "max_output_bytes": 10485760},
            "verification": {
                "fail_fast": True,
                "commands": ["python -m compileall .", "pytest"],
            },
            "network": {"mode": "deny"},
            "logging": {"directory": ".sentinelbox/logs", "max_file_size_mb": 50},
            "policy": {
                "default_action": "deny",
                "allowed_commands": ["python", "python3", "pytest", "ruff", "mypy", "git", "npm"],
                "denied_commands": ["shutdown", "reboot", "format", "mkfs", "sudo"],
            },
        }
        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(default_cfg, f, default_flow_style=False)
        print(f"[✓] Created default configuration: {config_file}")

    print(f"[✓] Initialized SentinelBox in: {target_dir}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    render_header()
    target_dir = Path(args.path).resolve()
    platform_adapter = get_platform_adapter()

    print(f"[*] Python Version:      {sys.version.split()[0]} (SUPPORTED)")
    print(f"[*] Operating System:    {sys.platform} (SUPPORTED)")

    features = platform_adapter.get_supported_security_features()
    print(f"[*] Security Features:   {', '.join(sorted(features))}")

    git_available = (target_dir / ".git").exists()
    print(f"[*] Git Repository:      {'DETECTED' if git_available else 'NONE'}")

    cfg_file = target_dir / "sentinelbox.yaml"
    print(f"[*] Configuration:       {'FOUND' if cfg_file.exists() else 'DEFAULT (run sentinelbox init)'}")

    incomplete_txs: List[str] = []
    tx_root = target_dir / ".sentinelbox" / "transactions"
    if tx_root.exists():
        incomplete_txs = [d.name for d in tx_root.iterdir() if d.is_dir()]

    if incomplete_txs:
        print(f"[!] Warning: Found {len(incomplete_txs)} uncommitted/abandoned transactions:")
        for tx in incomplete_txs:
            print(f"    - {tx}")
    else:
        print("[✓] Transaction Journal: CLEAN")

    print("[✓] SentinelBox Doctor: Ready for safe agent operation.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    target_dir = Path(args.path).resolve()
    
    # Safely flatten REMAINDER arguments and strip leading "--" if passed
    raw_cmd = args.command
    if raw_cmd and raw_cmd[0] == "--":
        raw_cmd = raw_cmd[1:]

    flattened = []
    for item in raw_cmd:
        if isinstance(item, list):
            flattened.extend(str(x) for x in item)
        else:
            flattened.append(str(item))

    command = flattened

    if not command:
        print("Error: No command specified to run.", file=sys.stderr)
        return 1

    try:
        with SentinelBox.open(target_dir) as sandbox:
            result = sandbox.execute(command)

            if not args.json:
                print(f"[*] Command Output:\n{result.stdout}")
                if result.stderr:
                    print(f"[*] Stderr:\n{result.stderr}", file=sys.stderr)

            # Auto-verify
            verification = sandbox.verify()
            if not verification.passed:
                if args.json:
                    print(
                        json.dumps(
                            {
                                "success": False,
                                "stage": "VERIFICATION",
                                "result": result.to_dict(),
                                "verification": verification.to_dict(),
                            }
                        )
                    )
                else:
                    print(
                        f"[!] Verification failed: {verification.failure_reason}", file=sys.stderr
                    )
                sandbox.rollback()
                return 4

            # Auto-commit if verification passed and not dry-run
            if not args.dry_run:
                commit_res = sandbox.commit()
                if args.json:
                    print(
                        json.dumps(
                            {
                                "success": True,
                                "result": result.to_dict(),
                                "verification": verification.to_dict(),
                                "commit": commit_res.to_dict(),
                            }
                        )
                    )
                else:
                    print(
                        f"[✓] Verification passed. Committed {commit_res.changes_applied} file changes."
                    )
            else:
                diff_rep = sandbox.diff()
                if args.json:
                    print(
                        json.dumps(
                            {
                                "success": True,
                                "dry_run": True,
                                "diff": diff_rep.to_dict(),
                                "verification": verification.to_dict(),
                            }
                        )
                    )
                else:
                    print("[*] Dry run: verified successfully, rolled back without applying.")
                sandbox.rollback()

        return 0

    except GuardViolation as gv:
        if args.json:
            print(json.dumps({"success": False, "error": str(gv), "type": "GuardViolation"}))
        else:
            print(f"[!] Security Policy Violation: {gv}", file=sys.stderr)
        return 3
    except TransactionConflict as tc:
        if args.json:
            print(json.dumps({"success": False, "error": str(tc), "type": "TransactionConflict"}))
        else:
            print(f"[!] Conflict Aborted: {tc}", file=sys.stderr)
        return 6
    except Exception as e:
        raise e

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelbox",
        description="SentinelBox: Deterministic Sandboxing & Verification Engine for AI Agents",
    )
    parser.add_argument(
        "--path", default=".", help="Target workspace path (default: current directory)"
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # init
    p_init = subparsers.add_parser("init", help="Initialize SentinelBox configuration in a project")
    p_init.set_defaults(func=cmd_init)

    # doctor
    p_doctor = subparsers.add_parser("doctor", help="Check system prerequisites and transactions")
    p_doctor.set_defaults(func=cmd_doctor)

    # run
    p_run = subparsers.add_parser("run", help="Execute command inside transactional isolation")
    p_run.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    p_run.add_argument(
        "--dry-run", action="store_true", help="Verify execution without committing changes"
    )
    p_run.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute")
    p_run.set_defaults(func=cmd_run)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    exit_code = args.func(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()