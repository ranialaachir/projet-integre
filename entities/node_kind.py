# entities/node_kind.py

from enum import Enum

class NodeKind(Enum):
	COMPUTER = "Computer"
	CONTAINER = "Container"
	DOMAIN = "Domain"
	GPO = "GPO"
	GROUP = "Group"
	OU = "OU"
	USER = "User"