# entities/edge.py

from .node import Node
from .edge_type import EdgeType

class Edge:
	def __init__(self, node_source: Node, node_end: Node, type: EdgeType):
		self.node_source = node_source
		self.node_end = node_end
		self.type = type
