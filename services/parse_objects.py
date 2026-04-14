# services/parse_objects.py

from entities.node import Node
from entities.node_kind import NodeKind
from entities.edge import Edge
from entities.edge_kind import EdgeKind
from entities.path import Path

# from : /api/v2/graphs/cypher
def parse_node(n: dict) -> Node | None:
    """Convert Node JSON to Node Object"""
    try:
        kind = NodeKind(n.get("kind", ""))
    except ValueError:
        print(f"  [!] Node Kind is Unknown : {n.get('kind')}")
        return None
    return Node(
        objectid   = n.get("objectId", ""),
        kind       = kind,
        label      = n.get("label", "Unknown"),
        properties = n.get("properties", {}),
    )

def parse_edge(e: dict) -> Edge | None:
    """Convertit un edge brut de l'API BloodHound en entité Edge."""
    try:
        kind = EdgeKind(e.get("kind", ""))
    except ValueError:
        print(f"  [!] Edge Kind is Unknown : {e.get('kind')}")
        return None

    source = e.get(e.get("source"))
    target = e.get(e.get("target"))

    if source is None or target is None:
        print(f"  [!] Target or Source Node are Empty")
        return None

    return Edge(source_node=source, goal_node=target, kind=kind)

def parse_path(source_node:Node, goal_node:Node, data:dict) -> Path:
	nodes_data = data["nodes"]
	nodes = {}
	for k, node_data in nodes_data.items():
		nodes[k] = Node(node_data["objectId"],
				node_data["kind"],
				node_data["label"],
				node_data["properties"]
			       )
	# Choose later on what to choose in properties
	edges_data = data["edges"]
	edges = []
	for edge_data in edges_data:
		edges.append(Edge(nodes[edge_data["source"]],
				  nodes[edge_data["target"]],
				  edge_data["kind"]
				 )
			     )
	return Path(source_node, goal_node, edges)