# strategies/bloodyad_base.py

from abc import ABC
from dataclasses import dataclass, field
from typing import Optional

from .exploit_strategy import ExploitStrategy
from entities.edge import Edge
from entities.node import Node
from entities.exploit_result import ExploitResult
from exceptions.hop_failed_error import HopFailedError
from services.printing import print_check, print_warning, print_info
from utils.platform import BACKEND
from utils.runner import run_tool
from utils.bloodyad import bloodyad_cmd
from repositories.acting_principal_repository import ActingPrincipalResolver, PrincipalResolution

# HARDCODED_PASSWORD = "iamthekingoftheworld"
HARDCODED_PASSWORD = "AutoPwn1344!"


@dataclass
class BloodyADBase(ExploitStrategy, ABC):
    edge: Edge
    _resolution: Optional[PrincipalResolution] = field(
        default=None, init=False, repr=False
    )

    # ── Properties ───────────────────────────────────────────────────────────

    @property
    def source(self) -> Node:
        """Raw BH source node — may be a Group, OU, etc."""
        return self.edge.source_node

    @property
    def target(self) -> Node:
        """Target node of the edge."""
        return self.edge.goal_node

    @property
    def attacker(self) -> Node:
        """
        The actual logon principal we authenticate as.
        - Before exploit(): falls back to raw source (display only)
        - After exploit():  the resolved User/Computer
        """
        if self._resolution is not None and self._resolution.ok:
            return self._resolution.principal
        return self.source

    # ── Resolution ───────────────────────────────────────────────────────────

    def _resolve_actor(self, creds: dict) -> PrincipalResolution:
        """
        Resolve edge.source_node into a usable logon principal.
        Result is cached — only runs once per strategy instance.
        """
        if self._resolution is not None:
            return self._resolution

        resolver = ActingPrincipalResolver()
        self._resolution = resolver.resolve(self.source, creds)
        return self._resolution

    # ── Credential preparation ────────────────────────────────────────────────

    def _prepare_creds(self, creds: dict) -> dict:
        """
        Build final creds for bloodyAD.

        Two paths:
          A) Runner already resolved and passed enriched creds (has 'username')
             → use them directly, skip re-resolution
          B) Called directly without pre-resolved creds
             → resolve from edge.source_node now
        """
        if BACKEND.name == "none":
            raise HopFailedError(
                self.edge,
                "No backend available. Run: pip install bloodyAD "
                "(or on Windows: wsl pip install bloodyAD)"
            )

        # Path A: runner passed pre-resolved creds
        if creds.get("username"):
            # store a synthetic resolution so self.attacker works correctly
            if self._resolution is None:
                self._resolution = PrincipalResolution(
                    ok=True,
                    principal=self.source,   # best we can do without re-querying
                    creds=creds,
                    reason="Pre-resolved by runner",
                    via=[self.source.label],
                )
            return creds

        # Path B: no username yet — resolve now
        resolution = self._resolve_actor(creds)
        if not resolution.ok:
            raise HopFailedError(
                self.edge,
                f"Cannot resolve a logon principal from '{self.source.label}': "
                f"{resolution.reason}"
            )
        return resolution.creds

    # ── Execution ─────────────────────────────────────────────────────────────

    def _run_bloodyad(
        self,
        creds: dict,
        subcommand: list[str],
        label: str,
        cwd: str = None,
    ) -> str:
        print_check(
            f"{label} [{BACKEND.name}]: "
            f"{self.attacker.label} ──▶ {self.target.label}"
        )
        ok, output = run_tool(bloodyad_cmd(creds, subcommand), cwd=cwd)
        # print(f"DEBUG _run_bloodyad ok={ok} output={output!r}")
        if not ok:
            raise HopFailedError(self.edge, f"{label} failed:\n{output}")
        return output

    def exploit(self, creds: dict) -> ExploitResult:
        # resolve / validate creds first
        creds = self._prepare_creds(creds)

        dispatch = getattr(self, "_DISPATCH", None)
        if dispatch is None:
            raise HopFailedError(
                self.edge,
                f"{self.__class__.__name__} has no _DISPATCH defined",
            )

        techniques = dispatch.get(self.target.kind)
        if not techniques:
            raise HopFailedError(
                self.edge,
                f"{self.edge.kind.value} on {self.target.kind.value} "
                f"— no known technique",
            )

        # Single technique — run directly
        if len(techniques) == 1:
            name, action = techniques[0]
            print_info(f"Using {name}...")
            return action(self, creds)

        # Multiple techniques — fallback chain
        errors = []
        for name, action in techniques:
            try:
                print_info(f"Trying {name}...")
                return action(self, creds)
            except HopFailedError as exc:
                first_line = str(exc).splitlines()[0]
                print_warning(f"{name} failed: {first_line}")
                errors.append(f"{name}: {first_line}")

        raise HopFailedError(
            self.edge,
            f"{self.edge.kind.value}: all techniques failed on "
            f"{self.target.kind.value}\n" + "\n".join(errors),
        )