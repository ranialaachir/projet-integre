# strategies/bloodyad_base.py
from abc import ABC
from dataclasses import dataclass, field

from .exploit_strategy import ExploitStrategy

from entities.edge import Edge
from entities.node import Node
from entities.exploit_result import ExploitResult

from exceptions.hop_failed_error import HopFailedError

from services.printing import print_check, print_warning, print_info

from utils.platform import BACKEND
from utils.runner import run_tool
from utils.bloodyad import bloodyad_cmd

from references.cred_store import enrich_creds

from repositories.acting_principal_repository import ActingPrincipalResolver, PrincipalResolution
from typing import Optional

HARDCODED_PASSWORD = "AutoPwn1344!"

@dataclass
class BloodyADBase(ExploitStrategy, ABC):
    edge: Edge
    _resolution: Optional[PrincipalResolution] = field(default=None, init=False, repr=False)

    @property
    def attacker(self) -> Node:
        """
        The actual logon principal we are acting as.
        Only valid after _resolve_actor() has been called (i.e. inside exploit()).
        """
        if self._resolution is None or not self._resolution.ok:
            # fallback to raw edge source before resolution runs
            # this is only safe for display purposes
            return self.edge.start
        return self._resolution.principal

    def _resolve_actor(self, creds: dict) -> PrincipalResolution:
        """
        Resolve edge.start into a usable logon principal.
        Called once per exploit(), result is cached.
        """
        if self._resolution is not None:
            return self._resolution

        resolver = ActingPrincipalResolver()
        self._resolution = resolver.resolve(self.edge.start, creds)
        return self._resolution

    def _prepare_creds(self, creds: dict) -> dict:
        """
        Resolve the acting principal from edge.start, then build enriched creds.
        Raises HopFailedError if no usable actor is found.
        """
        resolution = self._resolve_actor(creds)

        if not resolution.ok:
            raise HopFailedError(
                self.edge,
                f"Cannot resolve a logon principal from '{self.edge.start.label}': "
                f"{resolution.reason}"
            )

        if BACKEND.name == "none":
            raise HopFailedError(
                self.edge,
                "No backend available. Run: pip install bloodyAD "
                "(or on Windows: wsl pip install bloodyAD)"
            )
        
        # resolution.creds is already enriched by the resolver
        return resolution.creds

    def _run_bloodyad(self, creds: dict, subcommand: list[str], label: str, cwd: str = None ) -> str:
        print_check(
            f"{label} [{BACKEND.name}]: "
            f"{self.attacker.label} ──▶ {self.target.label}"
        )

        ok, output = run_tool(bloodyad_cmd(creds, subcommand), cwd=cwd)
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