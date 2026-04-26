# strategies/generic_write.py
from dataclasses import dataclass

from .bloodyad_base import BloodyADBase
from .techniques.ldap_techniques import ADTechniquesMixin
from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind
from entities.exploit_result import ExploitResult
from exceptions.hop_failed_error import HopFailedError
from services.printing import print_info, print_warning

@dataclass
class GenericWriteStrategy(ADTechniquesMixin, BloodyADBase):
    """
    GenericAll   = ALL permissions → can do anything including reset password
    GenericWrite = WRITE_PROP + WRITE_VALIDATED + READ_SD → can only write properties
    """
    _DISPATCH = {
        NodeKind.USER: [
            ("ShadowCredentials", ADTechniquesMixin._do_shadow_credentials),   # stealth
            ("TargetedKerberoast", ADTechniquesMixin._do_targeted_kerberoast), # fallback
        ],
        NodeKind.GROUP: [
            ("AddMember", ADTechniquesMixin._do_add_member),
        ],
        NodeKind.COMPUTER: [
            ("ShadowCredentials", ADTechniquesMixin._do_shadow_credentials),   # stealth
            ("RBCD", ADTechniquesMixin._do_rbcd),                              # fallback
        ],
    }

    def can_exploit(self) -> bool:
        return self.edge.kind == EdgeKind.GENERIC_WRITE