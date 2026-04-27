# repositories/graph_mutation_repository.py

from collections import defaultdict
from typing import Optional
from entities.node import Node
from .base_repository import BaseRepository


class GraphMutationRepository(BaseRepository):
    """
    Handles runtime graph state and optional BH/Neo4j synchronization.
    
    Responsibilities:
      - Track memberships added at runtime (local state)
      - Optionally push changes to Neo4j/BH so graph stays in sync
      - Provide queries that merge BH data + runtime state
    """

    def __init__(self, sync_to_bh: bool = False):
        super().__init__()
        self.sync_to_bh = sync_to_bh

        # ── Runtime state ─────────────────────────────────────────────────
        # group_object_id -> set of member Nodes added this session
        self._added_memberships: dict[str, set[Node]] = defaultdict(set)
        
        # track all mutations for potential rollback / reporting
        self._mutations: list[dict] = []

    # ══════════════════════════════════════════════════════════════════════
    # MEMBERSHIP
    # ══════════════════════════════════════════════════════════════════════

    def add_membership(self, member: Node, group: Node) -> None:
        """
        Record that `member` was added to `group` at runtime.
        Optionally sync to BH graph.
        """
        self._added_memberships[group.object_id].add(member)
        self._mutations.append({
            "type": "AddMember",
            "member": member.label,
            "member_id": member.object_id,
            "group": group.label,
            "group_id": group.object_id,
        })

        if self.sync_to_bh:
            self._sync_membership_to_bh(member, group)

    def remove_membership(self, member: Node, group: Node) -> None:
        """
        Record removal of `member` from `group`.
        Useful for cleanup / rollback.
        """
        members = self._added_memberships.get(group.object_id, set())
        members.discard(member)

        self._mutations.append({
            "type": "RemoveMember",
            "member": member.label,
            "member_id": member.object_id,
            "group": group.label,
            "group_id": group.object_id,
        })

        if self.sync_to_bh:
            self._unsync_membership_from_bh(member, group)

    def get_runtime_members(self, group: Node) -> set[Node]:
        """
        Get all members added to this group during this session.
        """
        return self._added_memberships.get(group.object_id, set())

    def is_runtime_member(self, member: Node, group: Node) -> bool:
        """
        Check if member was added to group during this session.
        """
        return member in self._added_memberships.get(group.object_id, set())

    # ══════════════════════════════════════════════════════════════════════
    # OWNERSHIP / ACL CHANGES
    # ══════════════════════════════════════════════════════════════════════

    def record_owner_change(self, target: Node, new_owner: Node) -> None:
        """
        Record that ownership of `target` was changed to `new_owner`.
        """
        self._mutations.append({
            "type": "OwnerChange",
            "target": target.label,
            "target_id": target.object_id,
            "new_owner": new_owner.label,
            "new_owner_id": new_owner.object_id,
        })

        if self.sync_to_bh:
            self._sync_owner_to_bh(target, new_owner)

    def record_acl_grant(
        self,
        target: Node,
        principal: Node,
        right: str,
    ) -> None:
        """
        Record that `principal` was granted `right` on `target`.
        e.g., GenericAll, WriteDacl, AddMember, etc.
        """
        self._mutations.append({
            "type": "ACLGrant",
            "target": target.label,
            "target_id": target.object_id,
            "principal": principal.label,
            "principal_id": principal.object_id,
            "right": right,
        })

        if self.sync_to_bh:
            self._sync_acl_to_bh(target, principal, right)

    # ══════════════════════════════════════════════════════════════════════
    # CREDENTIAL PIVOTS
    # ══════════════════════════════════════════════════════════════════════

    def record_credential_pivot(
        self,
        from_principal: Node,
        to_principal: Node,
        technique: str,
    ) -> None:
        """
        Record that we pivoted from one principal to another.
        e.g., ForceChangePassword, ShadowCredentials, etc.
        """
        self._mutations.append({
            "type": "CredentialPivot",
            "from": from_principal.label,
            "from_id": from_principal.object_id,
            "to": to_principal.label,
            "to_id": to_principal.object_id,
            "technique": technique,
        })

    # ══════════════════════════════════════════════════════════════════════
    # QUERIES (merge BH + runtime)
    # ══════════════════════════════════════════════════════════════════════

    def get_effective_group_members(self, group: Node) -> dict[str, Node]:
        """
        Query BH for group members, then merge with runtime additions.
        Returns dict of {object_id: Node}.
        """
        from services.parse_objects import parse_dict_node

        # 1. Query BH
        response = self.bh_request.bh_post(
            "/api/v2/graphs/cypher",
            {
                "query": f"""
                    MATCH (u)
                    WHERE (u:User OR u:Computer)
                      AND (u)-[:MemberOf*1..10]->(:Group {{objectid: '{group.object_id}'}})
                    RETURN u
                """,
                "include_properties": True,
            },
        )

        result: dict[str, Node] = {}

        if response:
            raw = response.get("data", {}).get("nodes", {})
            if raw:
                result = parse_dict_node(raw)

        # 2. Merge runtime additions
        for node in self.get_runtime_members(group):
            result[node.object_id] = node

        return result

    # ══════════════════════════════════════════════════════════════════════
    # REPORTING / ROLLBACK
    # ══════════════════════════════════════════════════════════════════════

    def get_mutations(self) -> list[dict]:
        """
        Get all mutations recorded this session.
        Useful for reporting or generating cleanup commands.
        """
        return self._mutations.copy()

    def clear_runtime_state(self) -> None:
        """
        Reset all runtime state. Does NOT undo changes in AD or BH.
        """
        self._added_memberships.clear()
        self._mutations.clear()

    def generate_cleanup_report(self) -> str:
        """
        Generate a human-readable report of what to clean up.
        """
        if not self._mutations:
            return "No mutations recorded."

        lines = ["# Cleanup Required", ""]

        for m in self._mutations:
            if m["type"] == "AddMember":
                lines.append(
                    f"- Remove {m['member']} from {m['group']}\n"
                    f"  net rpc group delmem \"{m['group']}\" \"{m['member']}\" -U ... "
                )
            elif m["type"] == "OwnerChange":
                lines.append(
                    f"- Restore owner of {m['target']} (changed to {m['new_owner']})"
                )
            elif m["type"] == "ACLGrant":
                lines.append(
                    f"- Remove {m['right']} grant: {m['principal']} -> {m['target']}"
                )
            elif m["type"] == "CredentialPivot":
                lines.append(
                    f"- Password/creds changed: {m['to']} (via {m['technique']})"
                )

        return "\n".join(lines)

    # ══════════════════════════════════════════════════════════════════════
    # BH SYNC (private)
    # ══════════════════════════════════════════════════════════════════════

    def _sync_membership_to_bh(self, member: Node, group: Node) -> None:
        """Push MemberOf edge to BH graph."""
        self.bh_request.bh_post(
            "/api/v2/graphs/cypher",
            {
                "query": f"""
                    MATCH (u {{objectid: '{member.object_id}'}})
                    MATCH (g {{objectid: '{group.object_id}'}})
                    MERGE (u)-[:MemberOf]->(g)
                """,
                "include_properties": False,
            },
        )

    def _unsync_membership_from_bh(self, member: Node, group: Node) -> None:
        """Remove MemberOf edge from BH graph."""
        self.bh_request.bh_post(
            "/api/v2/graphs/cypher",
            {
                "query": f"""
                    MATCH (u {{objectid: '{member.object_id}'}})-[r:MemberOf]->(g {{objectid: '{group.object_id}'}})
                    DELETE r
                """,
                "include_properties": False,
            },
        )

    def _sync_owner_to_bh(self, target: Node, new_owner: Node) -> None:
        """Push Owns edge to BH graph."""
        self.bh_request.bh_post(
            "/api/v2/graphs/cypher",
            {
                "query": f"""
                    MATCH (o {{objectid: '{new_owner.object_id}'}})
                    MATCH (t {{objectid: '{target.object_id}'}})
                    MERGE (o)-[:Owns]->(t)
                """,
                "include_properties": False,
            },
        )

    def _sync_acl_to_bh(self, target: Node, principal: Node, right: str) -> None:
        """Push ACL edge to BH graph."""
        self.bh_request.bh_post(
            "/api/v2/graphs/cypher",
            {
                "query": f"""
                    MATCH (p {{objectid: '{principal.object_id}'}})
                    MATCH (t {{objectid: '{target.object_id}'}})
                    MERGE (p)-[:{right}]->(t)
                """,
                "include_properties": False,
            },
        )