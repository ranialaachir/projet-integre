# services/pathfinding.py

from .base_repository import BaseRepository
from exceptions.no_path_error import NoPathError
from exceptions.api_error import ApiError
from entities.path import Path
from entities.node import Node
from services.parse_objects import parse_path

class PathfindingRepository(BaseRepository):
    def __init__(self):
        super().__init__()
        
    def get_path(self, source_node:Node, goal_node:Node) -> Path:
        query = (
			f"MATCH p = shortestPath((n:{source_node.kind.value}) -[*1..10]-> (m:{goal_node.kind.value})) "
			f"WHERE n.objectid = '{source_node.objectid}' "
			f"AND m.objectid = '{goal_node.objectid}' RETURN p"
		)
        
        path_result = self.bh_request.bh_post("/api/v2/graphs/cypher", {
			"query": query,
			"include_properties": True
		})
        
        if path_result is None:
            raise NoPathError(source_node, goal_node)
        path = path_result.get("data", {}).get("nodes", {}) if path_result else {} # this is repeated a lot, it should a util function :)
        if path is None:
            raise ApiError(0, "/api/v2/graphs/cypher", f"Could not find any real path.")
        return parse_path(source_node, goal_node, path)