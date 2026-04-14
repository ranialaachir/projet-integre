# utils/runner.py

import subprocess
from .platform import BACKEND
from services.printing import print_warning


def run_tool(args: list[str], timeout: int = 30) -> tuple[bool, str]:
    """
    Lance une commande avec le bon backend (natif ou WSL).
    Retourne (success, output).
    """
    cmd = BACKEND.prefix + args

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = (r.stdout + r.stderr).strip()
        return r.returncode == 0, output

    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, "Timeout"