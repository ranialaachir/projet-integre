# strategies/bloodyad_base.py
from abc import ABC
from dataclasses import dataclass

from .exploit_strategy import ExploitStrategy

from entities.edge import Edge
from entities.exploit_result import ExploitResult

from exceptions.hop_failed_error import HopFailedError

from services.printing import print_check, print_warning, print_info

from utils.platform import BACKEND
from utils.runner import run_tool
from utils.bloodyad import bloodyad_cmd

from references.cred_store import enrich_creds

HARDCODED_PASSWORD = "AutoPwn1344!"

@dataclass
class BloodyADBase(ExploitStrategy, ABC):
    edge: Edge

    # Do NOT define _DISPATCH here

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

    def exploit(self, creds: dict) -> ExploitResult:
        creds = self._prepare_creds(creds)

        dispatch = getattr(self, '_DISPATCH', None)
        if dispatch is None:
            raise HopFailedError(
                self.edge,
                f"{self.__class__.__name__} has no _DISPATCH defined"
            )

        techniques = dispatch.get(self.target.kind)
        if not techniques:
            raise HopFailedError(
                self.edge,
                f"{self.edge.kind.value} on {self.target.kind.value} "
                f"— no known technique"
            )

        # Single technique → run directly
        if len(techniques) == 1:
            name, action = techniques[0]
            print_info(f"Using {name}...")
            return action(self, creds)

        # Multiple techniques → fallback chain
        errors = []
        for name, action in techniques:
            try:
                print_info(f"Trying {name}...")
                return action(self, creds)
            except HopFailedError as e:
                first_line = str(e).splitlines()[0]
                print_warning(f"{name} failed: {first_line}")
                errors.append(f"{name}: {first_line}")
                continue

        raise HopFailedError(
            self.edge,
            f"{self.edge.kind.value}: all techniques failed on "
            f"{self.target.kind.value}\n" + "\n".join(errors)
        )
    


"""
@dataclass
class SomeStrategy(ADTechniquesMixin, BloodyADBase):
    _DISPATCH = { ... }            # what to do

    def can_exploit(self) -> bool:  # when to do it
        return ...
"""