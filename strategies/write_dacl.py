# strategies/write_daclpy

from dataclasses import dataclass

from .bloodyad_base import BloodyADBase
from .techniques.ldap_techniques import ADTechniquesMixin
from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind

@dataclass
class WriteDaclStrategy(ADTechniquesMixin, BloodyADBase):
    """
    WriteDACL → grant ourselves DCSync (domain) or GenericAll (user/group/computer).
    """
    _DISPATCH = {
        NodeKind.DOMAIN: [
            ("GrantDCSync", ADTechniquesMixin._do_grant_dcsync),
        ],
        NodeKind.USER: [
            ("GrantGenericAll", ADTechniquesMixin._do_grant_generic_all),
        ],
        NodeKind.GROUP: [
            ("GrantGenericAll", ADTechniquesMixin._do_grant_generic_all),
        ],
        NodeKind.COMPUTER: [
            ("GrantGenericAll", ADTechniquesMixin._do_grant_generic_all),
        ],
    }

    def can_exploit(self) -> bool:
        return self.edge.kind == EdgeKind.WRITE_DACL