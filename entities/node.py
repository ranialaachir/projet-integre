# entities/node.py

from .node_kind import NodeKind

class Node:
	def __init__(self, objectid: str, kind: NodeKind,
		     label: str, properties: dict):
		self.objectid = objectid
		self.kind = kind
		self.label = label
		self.properties = properties
