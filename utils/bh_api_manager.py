from .request import BHRequest


class BHAPIManager:
    def __init__(self, bh_request: BHRequest):
        self.req = bh_request

    def get_owned_sids(self) -> set[str]:
        """Récupère les ObjectIDs des nodes marqués comme 'Owned'."""
        path = "/api/v2/bloodhound-users/owned-objects"
        data = self.req.bh_get(path)
        if data and "data" in data:
            # On extrait uniquement les objectid pour une recherche rapide
            return {obj["objectid"] for obj in data["data"]}
        return set()

    def get_tier_zero_sids(self) -> set[str]:
        """Récupère les ObjectIDs des membres du groupe Tier Zero (admin_tier_0)."""
        path = "/api/v2/asset-isolation/asset-group-members?asset_group_tag=admin_tier_0"
        data = self.req.bh_get(path)
        if data and "data" in data:
            return {obj["objectid"] for obj in data["data"]}
        return set()