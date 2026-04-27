# services/acting_principal_resolver.py

from dataclasses import dataclass, field
from typing import Optional
from entities.node import Node
from entities.credentials import Credential
from entities.node_kind import NodeKind
from references.cred_store import *

"""
Principal Resolution Service
─────────────────────────────
Given ANY BloodHound node (User, Group, Computer, OU, Domain...),
find an actual logon-capable principal whose credentials we know.

Usage:
    from services.principal_resolver import PrincipalResolver

    resolver = PrincipalResolver(bh_client, cred_store)
    result   = resolver.resolve(node)

    if result:
        print(f"Use {result.username} with {result.secret}")

WE NEED LOGON PRINCIPAL (Computer & User)
Group had logon principals
The edge source is the authorization source

What should be preserved :
- edge.source_node = original BH source
- acting_principal = actual credentialed principal used to execute

LOGON_PRINCIPAL_KINDS = {
    NodeKind.USER,
    NodeKind.COMPUTER,
}

Group
Not a logon principal. Must resolve through membership.

User
Usable directly if you have creds.

Computer
Usable directly if you have machine creds/hash.

Domain / OU / GPO / Container / DNS zone / etc.
Not logon principals. Skip.
"""
LOGON_PRINCIPAL_KINDS = {
    NodeKind.USER,
    NodeKind.COMPUTER,
}

@dataclass
class PrincipalResolution:
    ok: bool
    principal: Optional[Node] = None
    creds: Optional[Credential] = None
    reason: str = ""
    via: list[str] = field(default_factory=list) 

class ActingPrincipalResolver:
    def __init__(self, bh):
        self.bh = bh

    def resolve(self, source_node:Node, base_creds:dict) -> PrincipalResolution:
        """
        Resolve a BloodHound source node to a usable logon principal.

        Rules:
          - User/Computer: use directly if we have creds
          - Group: find a recursive member (User/Computer) we have creds for
          - Anything else: not a logon principal => skip
        """
        kind = source_node.kind

        # 1) Directly logon-capable principal
        if kind in LOGON_PRINCIPAL_KINDS:
            username = source_node.sam()
            if has_creds(username):
                effective = enrich_creds({
                    **base_creds,
                    "username": username,
                })
                return PrincipalResolution(
                    ok=True,
                    principal=source_node,
                    creds=effective,
                    reason=f"Direct credentials available for {username}",
                    via=[source_node.label],
                )
            return PrincipalResolution(
                ok=False,
                reason=f"Source is a logon principal ({source_node.label}) but we have no creds for it",
            )
        
        # 2) Group => resolve member with creds
        if kind == NodeKind.GROUP:
            candidates = self._find_credentialed_group_members(source_node)
            if not candidates:
                return PrincipalResolution(
                    ok=False,
                    reason=(
                        f"Source is Group ({source_node.label}) but no credentialed "
                        f"user/computer members were found"
                    ),
                )
            actor = candidates[0] # CHOOSE First
            effective = enrich_creds({
                **base_creds,
                "username": actor.sam(),
            })
            return PrincipalResolution(
                ok=True,
                principal=actor,
                creds=effective,
                reason=f"Resolved via group membership: {actor.label} ∈ {source_node.label}",
                via=[actor.label, source_node.label],
            )
        
        # 3) Everything else => not authenticatable
        return PrincipalResolution(
            ok=False,
            reason=f"Source is {kind.name}, not a logon principal",
        )