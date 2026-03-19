#!/usr/bin/env python3
"""
SafeClaw sandbox runner.
Runs audit.py inside an ephemeral Docker container with strict isolation.
Falls back to direct execution if Docker is not available or --no-sandbox is set.
"""

import argparse
import os
import subprocess
import sys


def docker_available() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_in_sandbox(skill_abs_path: str, no_clawhub: bool) -> int:
    cmd = [
        "docker", "run",
        "--rm",
        "--network", "none",
        "--read-only",
        "--memory", "256m",
        "--cpus", "0.5",
        "-v", f"{skill_abs_path}:/audit:ro",
        "safeclaw-auditor:latest",
        "/audit",
        "--no-clawhub",  # always skip ClawHub inside sandbox (no network access)
    ]
    # --no-clawhub already included; keep param for API consistency

    try:
        result = subprocess.run(cmd, timeout=60)
        return result.returncode
    except subprocess.TimeoutExpired:
        print("ERROR: Sandbox timed out after 60s", file=sys.stderr)
        return 1


def run_direct(skill_path: str, no_clawhub: bool) -> int:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    audit_py = os.path.join(script_dir, "audit.py")

    cmd = [sys.executable, audit_py, skill_path]
    if no_clawhub:
        cmd.append("--no-clawhub")

    result = subprocess.run(cmd)
    return result.returncode


def main():
    parser = argparse.ArgumentParser(
        description="SafeClaw: run skill security audit (optionally sandboxed)"
    )
    parser.add_argument("skill_path", help="Path to the skill directory to audit")
    parser.add_argument(
        "--no-sandbox",
        action="store_true",
        help="Force direct execution without Docker sandbox",
    )
    parser.add_argument(
        "--no-clawhub",
        action="store_true",
        help="Skip ClawHub API checks (passed through to audit.py)",
    )
    args = parser.parse_args()

    skill_abs_path = os.path.abspath(args.skill_path)

    if not os.path.exists(skill_abs_path):
        print(f"ERROR: Path not found: {skill_abs_path}", file=sys.stderr)
        sys.exit(1)

    if args.no_sandbox:
        sys.exit(run_direct(skill_abs_path, args.no_clawhub))

    if docker_available():
        sys.exit(run_in_sandbox(skill_abs_path, args.no_clawhub))
    else:
        print("Docker not available — running without sandbox", file=sys.stderr)
        sys.exit(run_direct(skill_abs_path, args.no_clawhub))


if __name__ == "__main__":
    main()
