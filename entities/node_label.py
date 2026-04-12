# entities/node_label.py

from enum import Enum

class NodeLabel(Enum):
	COMPUTER = "Computer"
	DOMAIN = "Domain"
	GPO = "GPO"
	GROUP = "Group"
	OU = "OU"
	USER = "User"
