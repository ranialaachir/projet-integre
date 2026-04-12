# entities/path.py

from .node import Node
from .edge import Edge

class path:
	def __init__(self, start_node:Node, goal_node:Node, edges: list[Edge]):
		self.start_node = start_node
		self.goal_node = goal_node
		self.edges = edges

	@property
	def length(self):
		return len(self.edges)
