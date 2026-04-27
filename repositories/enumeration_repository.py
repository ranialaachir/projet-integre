# repositories/enumeration_repository.py

from repositories.base_repository import BaseRepository
from entities.node_kind import NodeKind
from entities.node import Node
from services.parse_objects import parse_dict_node
from exceptions.api_error import ApiError

class EnumerationRepository(BaseRepository): # Can be a sub folder if it gets too much
    def __init__(self):
        super().__init__()
    # enumerate nodes
    def _get_nodes(self, kind:NodeKind):
        query = ( #$src_id, $tgt_id with parameters
            f"MATCH (u:{kind.value}) RETURN u"
        )
        result = self.bh_request.bh_post("/api/v2/graphs/cypher", { # cypher query can be a util maybe?
            "query": query,
            "include_properties": True
        })
        nodes = result.get("data", {}).get("nodes", {}) if result else {}
        if nodes is None:
            raise ApiError(0, "/api/v2/graphs/cypher", f"Could not find any {kind.value}.")
        return parse_dict_node(nodes)
    
    def get_users(self) -> dict[str, Node]:
        return self._get_nodes(NodeKind.USER)
    
    def get_domains(self):
        return self._get_nodes(NodeKind.DOMAIN)
    
    def get_groups(self):
        return self._get_nodes(NodeKind.GROUP)
    
    def get_ous(self):
        return self._get_nodes(NodeKind.OU)
    
    def get_container(self):
        return self._get_nodes(NodeKind.CONTAINER)
    
    def get_gpos(self):
        return self._get_nodes(NodeKind.GPO)
    
    # enumerate high value nodes
    def get_high_value_nodes(self, kind:NodeKind=NodeKind.BASE):
        query = ( #$src_id, $tgt_id with parameters
            f"MATCH (zrt:{kind.value}) WHERE (zrt:tag_Zero_Tier) RETURN zrt"
        )
        tz_result = self.bh_request.bh_post("/api/v2/graphs/cypher", { # cypher query can be a util maybe?
            "query": query,
            "include_properties": True
        })
        tz_nodes = tz_result.get("data", {}).get("nodes", {}) if tz_result else {}
        if tz_nodes is None:
            raise ApiError(0, "/api/v2/graphs/cypher", f"Could not find any high-value nodes. Use GenericWrite!")
        return parse_dict_node(tz_nodes)
    
    def get_high_value_users(self) -> dict[str, Node]:
        return self.get_high_value_nodes(NodeKind.USER)
    
    def get_high_value_domains(self):
        return self.get_high_value_nodes(NodeKind.DOMAIN)
    
    def get_high_value_groups(self):
        return self.get_high_value_nodes(NodeKind.GROUP)
    
    def get_high_value_ous(self):
        return self.get_high_value_nodes(NodeKind.OU)
    
    def get_high_value_container(self):
        return self.get_high_value_nodes(NodeKind.CONTAINER)
    
    def get_high_value_gpos(self):
        return self.get_high_value_nodes(NodeKind.GPO)
    
    def get_kerberoastable_users(self):
        kerb_result = self.bh_request.bh_post("/api/v2/graphs/cypher", {
            "query": "MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true RETURN u",
            "include_properties": True
        })
        kerb_nodes = kerb_result.get("data", {}).get("nodes", {}) if kerb_result else {}
        if not kerb_nodes:
            raise ApiError(0, "/api/v2/graphs/cypher", "No Kerberoastable users found (or query failed).")
        return parse_dict_node(kerb_nodes)
    
    def locate_domain_admins_group(self):
        da_result = self.bh_request.bh_post("/api/v2/graphs/cypher", {
            "query": "MATCH (g:Group) WHERE g.name STARTS WITH 'DOMAIN ADMINS' RETURN g",
            "include_properties": True
        })
        da_nodes = da_result.get("data", {}).get("nodes", {}) if da_result else {}
        if not da_nodes:
            raise ApiError(0, "/api/v2/graphs/cypher", "Domain Admins group not found.")

        da_data    = list(da_nodes.values())[0]
        da_node    = Node(da_data["objectId"], NodeKind.GROUP, da_data["label"], da_data["properties"])
        return da_node
    
    def get_enabled_users(self):
        user_result = self.bh_request.bh_post("/api/v2/graphs/cypher", {
            "query": "MATCH (u:User) WHERE u.enabled = true RETURN u",
            "include_properties": True
        })
        user_nodes = user_result.get("data", {}).get("nodes", {}) if user_result else {}
        if not user_nodes:
            raise ApiError(0, "/api/v2/graphs/cypher", "No enabled users found.")

        return parse_dict_node(user_nodes)