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
        return data["data"]["nodes"]

    def get_users(self) -> dict[str, Node]:
        data = self._get_nodes(NodeKind.USER)
        return parse_dict_node(n=data)
    
    def get_domains(self):
        data = self._get_nodes(NodeKind.DOMAIN)
        return parse_dict_node(n=data)
    
    def get_groups(self):
        data = self._get_nodes(NodeKind.GROUP)
        return parse_dict_node(n=data)
    
    def get_ous(self):
        data = self._get_nodes(NodeKind.OU)
        return parse_dict_node(n=data)
    
    def get_container(self):
        data = self._get_nodes(NodeKind.CONTAINER)
        return parse_dict_node(n=data)
    
    def get_gpos(self):
        data = self._get_nodes(NodeKind.GPO)
        return parse_dict_node(n=data)