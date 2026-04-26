# utils/runner.py

import subprocess
import os
from .platform import BACKEND

SHADOW_CREDS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),  # project root
    "tmp", "shadow_creds"
)

def run_tool(args: list[str], timeout: int = 30, cwd: str = None) -> tuple[bool, str]:
    """For bloodyAD commands — prepends backend prefix."""
    cmd = BACKEND.prefix + args
    print(f"DEBUG : {args}")
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd
        )
        output = (r.stdout + r.stderr).strip()
        return r.returncode == 0, output
    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, "Timeout"