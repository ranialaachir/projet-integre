# strategies/generic_all.py
from dataclasses import dataclass

from .bloodyad_base import BloodyADBase
from .techniques.ldap_techniques import ADTechniquesMixin
from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind
from entities.exploit_result import ExploitResult
from exceptions.hop_failed_error import HopFailedError
from services.printing import print_info, print_warning

# TODO : Add _targeted_kerberoast() & _shadow_credentials_attack

@dataclass
class GenericAllStrategy(ADTechniquesMixin, BloodyADBase):
    """
        GenericAll is a permission, not a technique.
        It unlocks different techniques based on target type.
        
        Priority order (stealth first), This is the fallback chain :
        - User: ShadowCredentials → ForceChangePassword → TargetedKerberoast
        - Group: AddMember
        - Computer: ShadowCredentials → RBCD
    """
    _DISPATCH = {
        NodeKind.USER: [
            ("ShadowCredentials", ADTechniquesMixin._do_shadow_credentials),
            ("ForceChangePassword", ADTechniquesMixin._do_force_change_password),
            ("TargetedKerberoast", ADTechniquesMixin._do_targeted_kerberoast),
        ],
        NodeKind.GROUP: [
            ("AddMember", ADTechniquesMixin._do_add_member),
        ],
        NodeKind.COMPUTER: [
            ("ShadowCredentials", ADTechniquesMixin._do_shadow_credentials),
            ("RBCD", ADTechniquesMixin._do_rbcd),
        ],
    }

    def can_exploit(self) -> bool:
        return self.edge.kind == EdgeKind.GENERIC_ALL 

# ShadowCredentials requires PKINIT support.