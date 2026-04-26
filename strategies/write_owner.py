# strategies/write_owner.py
from dataclasses import dataclass

from .bloodyad_base import BloodyADBase
from .techniques.ldap_techniques import ADTechniquesMixin
from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind

@dataclass
class WriteOwnerStrategy(ADTechniquesMixin, BloodyADBase):
    """
    WriteOwner → take ownership, then grant GenericAll via WriteDACL.
    """
    _DISPATCH = {
        NodeKind.USER: [
            ("TakeOwnership+GrantGenericAll", ADTechniquesMixin._do_take_ownership_then_generic_all),
        ],
        NodeKind.GROUP: [
            ("TakeOwnership+GrantGenericAll", ADTechniquesMixin._do_take_ownership_then_generic_all),
        ],
        NodeKind.COMPUTER: [
            ("TakeOwnership+GrantGenericAll", ADTechniquesMixin._do_take_ownership_then_generic_all),
        ],
        NodeKind.DOMAIN: [
            ("TakeOwnership+GrantDCSync", ADTechniquesMixin._do_take_ownership_then_generic_all),
        ],
    }

    def can_exploit(self) -> bool:
        return self.edge.kind == EdgeKind.WRITE_OWNER