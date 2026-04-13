# entities/path.py

from .node import Node
from .edge import Edge

class Path:
	def __init__(self, source_node:Node, goal_node:Node, edges: list[Edge]):
		self.source_node = source_node
		self.goal_node = goal_node
		self.edges = edges

	@property
	def length(self):
		return len(self.edges)
