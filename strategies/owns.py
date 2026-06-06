# strategies/owns.py

from dataclasses import dataclass

from .bloodyad_base import BloodyADBase
from .techniques.ldap_techniques import ADTechniquesMixin
from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind

@dataclass
class OwnsStrategy(ADTechniquesMixin, BloodyADBase):
    """
    Owns → already owner, skip TakeOwnership, go straight to GenericAll.
    """
    _DISPATCH = {
        NodeKind.USER: [
            ("GrantGenericAll", ADTechniquesMixin._do_grant_generic_all),
        ],
        NodeKind.GROUP: [
            ("GrantGenericAll", ADTechniquesMixin._do_grant_generic_all),
        ],
        NodeKind.COMPUTER: [
            ("GrantGenericAll", ADTechniquesMixin._do_grant_generic_all),
        ],
        NodeKind.DOMAIN: [
            ("GrantDCSync", ADTechniquesMixin._do_grant_dcsync),
        ],
    }

    def can_exploit(self) -> bool:
        return self.edge.kind == EdgeKind.OWNS