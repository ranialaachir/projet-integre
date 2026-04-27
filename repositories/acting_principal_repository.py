# services/acting_principal_resolver.py

from dataclasses import dataclass, field
from typing import Optional
from entities.node import Node
from entities.credentials import Credential
from entities.node_kind import NodeKind
from references.cred_store import *
from .base_repository import BaseRepository
from services.parse_objects import parse_dict_node

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

class ActingPrincipalResolver(BaseRepository):
    def __init__(self):
        super().__init__()

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
            if not has_creds(username):
                return PrincipalResolution(
                    ok=False,
                    reason=(
                        f"Source is a logon principal ({source_node.label}) "
                        f"but we have no creds for it"
                    ),
                )

            effective = enrich_creds({**base_creds, "username": username})
            return PrincipalResolution(
                ok=True,
                principal=source_node,
                creds=effective,
                reason=f"Direct credentials available for {username}",
                via=[source_node.label],
            )
        # TODO : Add changes of the path ???
        # 2) Group => resolve member with creds
        if kind == NodeKind.GROUP:
            members = self._find_group_members(source_node.label)
            if not members:
                return PrincipalResolution(
                    ok=False,
                    reason=(
                        f"Source is Group ({source_node.label}) but no "
                        f"user/computer members were found"
                    ),
                )

            # Recursively resolve each member — handles nested groups too
            for member in members.values():
                resolution = self.resolve(member, base_creds)
                if resolution.ok:
                    # Append the group to the via chain so callers can see the path
                    resolution.via.append(source_node.label)
                    resolution.reason = (
                        f"Resolved via group membership: "
                        f"{resolution.principal.label} ∈ {source_node.label}"
                    )
                    return resolution

            return PrincipalResolution(
                ok=False,
                reason=(
                    f"Source is Group ({source_node.label}) but no credentialed "
                    f"user/computer members were found"
                ),
            )
        
        # 3) Everything else => not authenticatable
        return PrincipalResolution(
            ok=False,
            reason=f"Source is {kind.name}, not a logon principal",
        )
    
    def _find_group_members(self,group_name:str) -> dict[str, Node] | None:
        response = self.bh_request.bh_post(
            "/api/v2/graphs/cypher",
            {
                "query": f"""
                    MATCH (u)
                    WHERE (u:User OR u:Computer)
                      AND (u)-[:MemberOf*1..10]->(:Group {{name: '{group_name}'}})
                    RETURN u
                """,
                "include_properties": True,
            },
        )

        if not response:
            return {}

        raw_nodes = response.get("data", {}).get("nodes", {})
        if not raw_nodes:
            return {}

        return parse_dict_node(raw_nodes)