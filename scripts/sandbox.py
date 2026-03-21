#!/usr/bin/env python3
"""
SafeClaw sandbox runner — v2.1
Multi-platform sandbox cascade: Docker → bubblewrap → firejail → sandbox-exec → fallback.
Falls back gracefully with interactive install helper when no sandbox is found.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _cmd_exists(name: str) -> bool:
    return shutil.which(name) is not None


def _run_check(cmd: list, timeout: int = 5) -> bool:
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return False


def docker_available() -> bool:
    return _cmd_exists("docker") and _run_check(["docker", "info"], timeout=5)


def bwrap_available() -> bool:
    return _cmd_exists("bwrap") and _run_check(["bwrap", "--version"], timeout=5)


def firejail_available() -> bool:
    return _cmd_exists("firejail") and _run_check(["firejail", "--version"], timeout=5)


def sandbox_exec_available() -> bool:
    return sys.platform == "darwin" and _cmd_exists("sandbox-exec")


# ---------------------------------------------------------------------------
# Sandbox runners
# ---------------------------------------------------------------------------

def run_docker(skill_abs_path: str, no_clawhub: bool) -> int:
    print("Using Docker sandbox (strongest isolation)", file=sys.stderr)
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
        "--no-clawhub",  # network not available inside; always skip ClawHub
    ]
    try:
        result = subprocess.run(cmd, timeout=60)
        return result.returncode
    except subprocess.TimeoutExpired:
        print("ERROR: Docker sandbox timed out after 60s", file=sys.stderr)
        return 1


def run_bwrap(skill_abs_path: str, no_clawhub: bool) -> int:
    print("Using bubblewrap sandbox (good isolation)", file=sys.stderr)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    audit_py = os.path.join(script_dir, "audit.py")

    # Copy audit.py to a temp dir so bwrap can bind-mount it read-only
    tmp_dir = tempfile.mkdtemp(prefix="safeclaw-bwrap-")
    try:
        tmp_audit = os.path.join(tmp_dir, "audit.py")
        shutil.copy2(audit_py, tmp_audit)

        cmd = [
            "bwrap",
            "--ro-bind", skill_abs_path, "/audit",
            "--ro-bind", tmp_audit, "/app/audit.py",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/etc", "/etc",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--unshare-net",
            "--unshare-pid",
            "--die-with-parent",
            "--new-session",
            sys.executable, "/app/audit.py", "/audit",
        ]
        if no_clawhub:
            cmd.append("--no-clawhub")
        else:
            cmd.append("--no-clawhub")  # no network in bwrap; always skip

        result = subprocess.run(cmd, timeout=60)
        return result.returncode
    except subprocess.TimeoutExpired:
        print("ERROR: bubblewrap sandbox timed out after 60s", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def run_firejail(skill_abs_path: str, no_clawhub: bool) -> int:
    print("Using firejail sandbox (good isolation)", file=sys.stderr)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    audit_py = os.path.join(script_dir, "audit.py")

    cmd = [
        "firejail",
        "--quiet",
        "--net=none",
        "--private-tmp",
        f"--read-only={skill_abs_path}",
        sys.executable, audit_py, skill_abs_path,
    ]
    if no_clawhub:
        cmd.append("--no-clawhub")
    else:
        cmd.append("--no-clawhub")  # no network in firejail; always skip

    try:
        result = subprocess.run(cmd, timeout=60)
        return result.returncode
    except subprocess.TimeoutExpired:
        print("ERROR: firejail sandbox timed out after 60s", file=sys.stderr)
        return 1


def run_sandbox_exec(skill_abs_path: str, no_clawhub: bool) -> int:
    print("Using macOS sandbox-exec (basic isolation)", file=sys.stderr)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    audit_py = os.path.join(script_dir, "audit.py")

    profile = (
        "(version 1)"
        "(deny default)"
        "(allow process-exec)"
        "(allow process-fork)"
        "(allow file-read*)"
        "(deny network*)"
    )

    cmd = [
        "sandbox-exec", "-p", profile,
        sys.executable, audit_py, skill_abs_path,
    ]
    if no_clawhub:
        cmd.append("--no-clawhub")
    else:
        cmd.append("--no-clawhub")  # no network allowed; always skip

    try:
        result = subprocess.run(cmd, timeout=60)
        return result.returncode
    except subprocess.TimeoutExpired:
        print("ERROR: sandbox-exec timed out after 60s", file=sys.stderr)
        return 1


def run_direct(skill_path: str, no_clawhub: bool) -> int:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    audit_py = os.path.join(script_dir, "audit.py")

    cmd = [sys.executable, audit_py, skill_path]
    if no_clawhub:
        cmd.append("--no-clawhub")

    result = subprocess.run(cmd)
    return result.returncode


# ---------------------------------------------------------------------------
# Interactive fallback helper
# ---------------------------------------------------------------------------

def interactive_install_helper(skill_path: str, no_clawhub: bool) -> int:
    """Prompt user to install a sandbox or run without isolation."""
    is_tty = sys.stdin.isatty()

    if not is_tty:
        print("WARNING: No sandbox available — running without isolation", file=sys.stderr)
        return run_direct(skill_path, no_clawhub)

    print("""
No sandbox runtime found. Available options:

[1] Install bubblewrap (recommended for Linux — lightweight, no root needed)
    sudo apt install bubblewrap   # Debian/Ubuntu
    sudo dnf install bubblewrap   # Fedora/RHEL

[2] Install firejail
    sudo apt install firejail

[3] Install Docker
    https://docs.docker.com/get-docker/

[4] Run without sandbox (not recommended for untrusted skills)

Choose [1-4]: """, end="", flush=True)

    try:
        choice = input().strip()
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.", file=sys.stderr)
        return 1

    if choice == "1":
        print("\nInstall bubblewrap with:", file=sys.stderr)
        print("  sudo apt install bubblewrap   # Debian/Ubuntu", file=sys.stderr)
        print("  sudo dnf install bubblewrap   # Fedora/RHEL", file=sys.stderr)
        print("Then re-run sandbox.py.", file=sys.stderr)
        return 1
    elif choice == "2":
        print("\nInstall firejail with:", file=sys.stderr)
        print("  sudo apt install firejail", file=sys.stderr)
        print("Then re-run sandbox.py.", file=sys.stderr)
        return 1
    elif choice == "3":
        print("\nInstall Docker: https://docs.docker.com/get-docker/", file=sys.stderr)
        print("Then re-run sandbox.py.", file=sys.stderr)
        return 1
    elif choice == "4":
        print("WARNING: Running without sandbox", file=sys.stderr)
        return run_direct(skill_path, no_clawhub)
    else:
        print("Invalid choice — aborting.", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# Sandbox selector
# ---------------------------------------------------------------------------

SANDBOX_RUNNERS = {
    "docker":       (docker_available,       run_docker),
    "bwrap":        (bwrap_available,        run_bwrap),
    "firejail":     (firejail_available,     run_firejail),
    "sandbox-exec": (sandbox_exec_available, run_sandbox_exec),
}


def pick_sandbox(forced: str | None):
    """Return (runner_fn, name) for the best available sandbox, or (None, None)."""
    if forced:
        if forced not in SANDBOX_RUNNERS:
            print(f"ERROR: Unknown sandbox '{forced}'. Valid: {', '.join(SANDBOX_RUNNERS)}", file=sys.stderr)
            sys.exit(1)
        check_fn, runner_fn = SANDBOX_RUNNERS[forced]
        if not check_fn():
            print(f"ERROR: Forced sandbox '{forced}' is not available on this system.", file=sys.stderr)
            sys.exit(1)
        return runner_fn, forced

    for name, (check_fn, runner_fn) in SANDBOX_RUNNERS.items():
        if check_fn():
            return runner_fn, name

    return None, None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SafeClaw: run skill security audit inside an isolated sandbox"
    )
    parser.add_argument("skill_path", help="Path to the skill directory to audit")
    parser.add_argument(
        "--no-sandbox",
        action="store_true",
        help="Force direct execution without any sandbox",
    )
    parser.add_argument(
        "--no-clawhub",
        action="store_true",
        help="Skip ClawHub API checks (passed through to audit.py)",
    )
    parser.add_argument(
        "--sandbox",
        choices=list(SANDBOX_RUNNERS.keys()),
        default=None,
        help="Force a specific sandbox runtime",
    )
    args = parser.parse_args()

    skill_abs_path = os.path.abspath(args.skill_path)

    if not os.path.exists(skill_abs_path):
        print(f"ERROR: Path not found: {skill_abs_path}", file=sys.stderr)
        sys.exit(1)

    # ------------------------------------------------------------------
    # Self-audit detection: auditing our own skill directory → run direct
    # (sandbox sees paths differently; self-audit doesn't need isolation)
    # ------------------------------------------------------------------
    this_skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        if os.path.samefile(skill_abs_path, this_skill_dir):
            print(
                "Self-audit detected — sandbox not needed (auditing own code)",
                file=sys.stderr,
            )
            sys.exit(run_direct(skill_abs_path, args.no_clawhub))
    except (OSError, ValueError):
        pass

    # ------------------------------------------------------------------
    # --no-sandbox flag → run direct immediately
    # ------------------------------------------------------------------
    if args.no_sandbox:
        print("WARNING: Running without sandbox", file=sys.stderr)
        sys.exit(run_direct(skill_abs_path, args.no_clawhub))

    # ------------------------------------------------------------------
    # Windows → no sandbox support yet
    # ------------------------------------------------------------------
    if sys.platform == "win32":
        print(
            "Windows detected — sandbox not available yet. Running without isolation.",
            file=sys.stderr,
        )
        sys.exit(run_direct(skill_abs_path, args.no_clawhub))

    # ------------------------------------------------------------------
    # Cascade: pick best sandbox
    # ------------------------------------------------------------------
    runner_fn, sandbox_name = pick_sandbox(args.sandbox)

    if runner_fn is not None:
        sys.exit(runner_fn(skill_abs_path, args.no_clawhub))

    # ------------------------------------------------------------------
    # No sandbox found → interactive helper
    # ------------------------------------------------------------------
    sys.exit(interactive_install_helper(skill_abs_path, args.no_clawhub))


if __name__ == "__main__":
    main()
