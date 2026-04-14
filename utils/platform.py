# utils/platform.py

import sys
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class Backend:
    name:   str
    prefix: list[str]


def detect_backend() -> Backend:
    # ── Linux / Mac : bloodyAD natif ─────────────────────────────────────────
    if shutil.which("bloodyAD"):
        return Backend(name="bloodyad", prefix=["bloodyAD"])

    # ── Windows : cherche via WSL avec shell login ────────────────────────────
    if sys.platform == "win32" and shutil.which("wsl"):
        result = subprocess.run(
            # bash -l = login shell → charge .bashrc/.profile → PATH complet
            ["wsl", "bash", "-lc", "which bloodyAD 2>/dev/null || echo NOTFOUND"],
            capture_output=True, text=True
        )
        path = result.stdout.strip()
        if path and path != "NOTFOUND":
            return Backend(name="wsl_bloodyad", prefix=["wsl", path])

    return Backend(name="none", prefix=[])


BACKEND: Backend = detect_backend()