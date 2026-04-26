# strategies/force_change_password.py

from dataclasses import dataclass
from .bloodyad_base import BloodyADBase
from .techniques.ldap_techniques import ADTechniquesMixin
from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind


@dataclass
class ForceChangePasswordStrategy(ADTechniquesMixin, BloodyADBase):
    _DISPATCH = {
        NodeKind.USER: [
            ("ForceChangePassword", ADTechniquesMixin._do_force_change_password),
        ],
    }

    def can_exploit(self) -> bool:
        return (
            self.edge.kind == EdgeKind.FORCE_CHANGE_PW
            and self.target.kind == NodeKind.USER
        )