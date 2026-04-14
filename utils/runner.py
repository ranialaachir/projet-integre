# utils/runner.py

import subprocess
from .platform import BACKEND
from services.printing import print_warning


def run_tool(args: list[str], timeout: int = 30) -> tuple[bool, str]:
    """For bloodyAD commands — prepends backend prefix."""
    cmd = BACKEND.prefix + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = (r.stdout + r.stderr).strip()
        return r.returncode == 0, output
    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, "Timeout"


def run_system_tool(args: list[str], timeout: int = 30) -> tuple[bool, str]:
    """For native system tools (net, smbclient, etc.) — no backend prefix."""
    # On Windows, route through WSL
    from .platform import BACKEND
    if BACKEND.name == "wsl_bloodyad":
        cmd = ["wsl"] + args
    else:
        cmd = args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = (r.stdout + r.stderr).strip()
        return r.returncode == 0, output
    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, "Timeout"