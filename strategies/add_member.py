# strategies/add_member.py
from dataclasses import dataclass

from .bloodyad_base import BloodyADBase
from .techniques.ldap_techniques import ADTechniquesMixin
from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind
from entities.exploit_result import ExploitResult


@dataclass
class AddMemberStrategy(ADTechniquesMixin, BloodyADBase):
    def can_exploit(self) -> bool:
        return (
            self.edge.kind == EdgeKind.ADD_MEMBER
            and self.target.kind == NodeKind.GROUP
        )

    def exploit(self, creds: dict) -> ExploitResult:
        creds = self._prepare_creds(creds)
        return self._do_add_member(creds)