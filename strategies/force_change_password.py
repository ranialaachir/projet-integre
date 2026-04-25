# strategies/force_change_password.py
from dataclasses import dataclass

from .bloodyad_base import BloodyADBase
from .ad_techniques import ADTechniquesMixin
from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind
from entities.exploit_result import ExploitResult


@dataclass
class ForceChangePasswordStrategy(ADTechniquesMixin, BloodyADBase):
    def can_exploit(self) -> bool:
        return (
            self.edge.kind == EdgeKind.FORCE_CHANGE_PW
            and self.target.kind == NodeKind.USER
        )

    def exploit(self, creds: dict) -> ExploitResult:
        creds = self._prepare_creds(creds)
        return self._do_force_change_password(creds)