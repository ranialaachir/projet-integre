# strategies/bloodyad_base.py
from abc import ABC
from dataclasses import dataclass

from .exploit_strategy import ExploitStrategy
from entities.edge import Edge
from exceptions.hop_failed_error import HopFailedError
from services.printing import print_check
from utils.platform import BACKEND
from utils.runner import run_tool
from utils.bloodyad import bloodyad_cmd
from references.cred_store import enrich_creds

HARDCODED_PASSWORD = "AutoPwn1344!"


@dataclass
class BloodyADBase(ExploitStrategy, ABC):
    edge: Edge

    def _prepare_creds(self, creds: dict) -> dict:
        attacker_sam = self.attacker.sam()
        merged = {**creds, "username": attacker_sam}

        try:
            merged = enrich_creds(merged)
        except (KeyError, ValueError):
            raise HopFailedError(
                self.edge,
                f"No credentials available for attacker '{attacker_sam}'. "
                f"Cannot exploit {self.edge.kind.value}."
            )

        if BACKEND.name == "none":
            raise HopFailedError(
                self.edge,
                "No backend available. Run: pip install bloodyAD "
                "(or on Windows: wsl pip install bloodyAD)"
            )
        return merged

    def _run_bloodyad(self, creds: dict, subcommand: list[str], label: str) -> str:
        print_check(
            f"{label} [{BACKEND.name}]: "
            f"{self.attacker.label} ──▶ {self.target.label}"
        )

        ok, output = run_tool(bloodyad_cmd(creds, subcommand))
        if not ok:
            raise HopFailedError(self.edge, f"{label} failed:\n{output}")
        return output