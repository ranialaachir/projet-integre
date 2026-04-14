# entities/edge.py

from .node import Node
from .edge_kind import EdgeKind

class Edge:
	def __init__(self, source_node: Node, goal_node: Node, kind: EdgeKind):
		self.source_node = source_node
		self.goal_node = goal_node
		self.kind = kind