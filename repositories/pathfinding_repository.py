# services/pathfinding.py

from .base_repository import BaseRepository
from exceptions.no_path_error import NoPathError
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
        data = path_result.get("data", {})
        if data is None:
            raise NoPathError(source_node, goal_node)
        return parse_path(source_node, goal_node, data)