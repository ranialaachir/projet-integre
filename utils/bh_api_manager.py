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