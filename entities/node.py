# entities/node.py

from .node_label import NodeLabel

class Node:
	def __init__(self, objectid: str, label: NodeLabel,
		     name: str, properties: dict):
		self.objectid = objectid
		self.label = label
		self.name = name
		self.properties = properties
