
from entities import edge_kind

from .request import BHRequest


class BHAPIManager:
    def __init__(self, bh_request: BHRequest):
        self.req = bh_request

    def get_owned_sids(self) -> set[str]:
        """Récupère les ObjectIDs des nodes marqués comme Owned."""
        data = self.req.bh_get("/api/v2/bloodhound-users/owned-objects")
        if not data or "data" not in data:
            return set()
        return {obj.get("objectid") or obj.get("object_id", "") for obj in data["data"]}

    def get_tier_zero_sids(self) -> set[str]:
        """Récupère les ObjectIDs des membres du Tier Zero via Cypher."""
        result = self.req.bh_post("/api/v2/graphs/cypher", {
            "query": "MATCH (n) WHERE n.highvalue = true RETURN n",
            "include_properties": True
        })
        if not result or "data" not in result:
            return set()
        nodes = result["data"].get("nodes", {})
        return {
            node.get("objectId") or node.get("objectid", "")
            for node in nodes.values()
        }

    def get_edges_by_kind(self, edge_kind: str) -> list:
        """Récupère les arêtes avec les propriétés complètes de src et dst."""
        result = self.req.bh_post("/api/v2/graphs/cypher", {
            "query": f"""
                MATCH (src)-[r:{edge_kind}]->(dst)
                RETURN src, r, dst
                LIMIT 10
            """,
            "include_properties": True
        })
        if not result or "data" not in result:
            return []

        nodes     = result["data"].get("nodes", {})   # dict { "44": {...}, "46": {...} }
        edges_raw = result["data"].get("edges", [])

        # On enrichit chaque edge avec les données complètes de ses nodes
        enriched = []
        for edge in edges_raw:
            src_id = str(edge["source"])
            dst_id = str(edge["target"])
            enriched.append({
                "edge":   edge,
                "source": nodes.get(src_id, {}),
                "target": nodes.get(dst_id, {})
            })
        return enriched
    
    def get_node_by_id(self, node_id: str) -> dict:
        """Résout un ID numérique BH en propriétés complètes du node."""
        result = self.req.bh_get(f"/api/v2/nodes/{node_id}")
        if not result or "data" not in result:
            return {}
        return result["data"]

    def get_edges_as_objects(self, edge_kind: str) -> list:
        from entities.node import Node
        from entities.edge import Edge
        from entities.edge_kind import EdgeKind
        from entities.node_kind import NodeKind

        raw_edges = self.get_edges_by_kind(edge_kind)
        edges     = []

        for item in raw_edges:
            src_data = item["source"]
            dst_data = item["target"]

            if not src_data or not dst_data:
                continue

            try:
                source_node = Node(
                    objectid   = src_data.get("objectId", ""),
                    kind       = NodeKind(src_data.get("kind", "User")),
                    label      = src_data.get("label", ""),
                    properties = src_data.get("properties", {})
                )
                target_node = Node(
                    objectid   = dst_data.get("objectId", ""),
                    kind       = NodeKind(dst_data.get("kind", "User")),
                    label      = dst_data.get("label", ""),
                    properties = dst_data.get("properties", {})
                )
            except ValueError as e:
                # NodeKind inconnu (ex: Tag_Tier_Zero) → on skip
                print(f"[WARN] NodeKind inconnu, edge ignoré : {e}")
                continue

            edges.append(Edge(
                source_node = source_node,
                goal_node   = target_node,
                kind        = EdgeKind.WRITE_OWNER
            ))

        return edges
