# strategies/add_member.py

from dataclasses import dataclass
from .bloodyad_base import BloodyADBase
from .techniques.ldap_techniques import ADTechniquesMixin
from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind


@dataclass
class AddMemberStrategy(ADTechniquesMixin, BloodyADBase):
    _DISPATCH = {
        NodeKind.GROUP: [
            ("AddMember", ADTechniquesMixin._do_add_member),
        ],
    }

    def can_exploit(self) -> bool:
        return (
            self.edge.kind == EdgeKind.ADD_MEMBER
            and self.target.kind == NodeKind.GROUP
        )