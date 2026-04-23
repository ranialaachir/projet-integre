# services/enumeration.py

from utils.request import BHRequest
from entities.node_kind import NodeKind
from entities.node import Node
from .parse_objects import parse_dict_node

class Enumerations:
    def __init__(self, bh_request:BHRequest):
        self.bh_request = bh_request

    def _get_nodes(self, kind:NodeKind):
        query = ( #$src_id, $tgt_id with parameters
            f"MATCH (u:{kind.value}) RETURN u"
        )
        data = self.bh_request.bh_post("/api/v2/graphs/cypher", { # cypher query can be a util maybe?
            "query": query,
            "include_properties": True
        })
        # Add exception
        return parse_dict_node(data["data"]["nodes"])
    
    def _get_tier_zero_nodes(self, kind:NodeKind=None):
        query = ( #$src_id, $tgt_id with parameters
            f"MATCH (u:{kind.value}) WHERE (u:tag_Zero_Tier) RETURN u"
        )
        data = self.bh_request.bh_post("/api/v2/graphs/cypher", { # cypher query can be a util maybe?
            "query": query,
            "include_properties": True
        })
        # Add exception
        return data["data"]["nodes"]

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