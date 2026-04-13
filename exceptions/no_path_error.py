# exceptions/no_path_error.py

from .auto_pwn_exception import AutoPwnException
from entities.node import Node

class NoPathError(AutoPwnException):
	"""
	If a Cypher query returns '0' paths to target.
	No route from node X to node Y.
	"""
	def __init__(self, start_node:Node, goal_node:Node):
		self.start_node = start_node
		self.goal_node = goal_node
		super().__init__(
			f"Finding Path Failed "
			f"No Path ({start_node.label} --> {goal_node.label})"
		)
