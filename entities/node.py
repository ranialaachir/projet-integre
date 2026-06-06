# entities/node.py

from dataclasses import dataclass, field
from typing import Any
from .node_kind import NodeKind

@dataclass(frozen=True)
class Node:
	objectid: str
	kind: NodeKind
	label: str
	properties: dict[str, Any] = field(default_factory=dict) # VF : choose which attributes to store here

	def __post_init__(self):
		if not self.label:
			object.__setattr__(self, "label", f"{self.kind.value}@{self.objectid}")

	def __str__(self):
		return self.label
	
	def is_user(self) -> bool:
		return self.kind == NodeKind.USER
	
	def is_group(self) -> bool:
		return self.kind == NodeKind.GROUP
	
	def is_computer(self) -> bool:
		return self.kind == NodeKind.COMPUTER

	def is_domain(self) -> bool:
		return self.kind == NodeKind.DOMAIN

	def is_container(self) -> bool:
		return self.kind == NodeKind.CONTAINER
	
	def is_ou(self) -> bool:
		return self.kind == NodeKind.OU

	def is_gpo(self) -> bool:
		return self.kind == NodeKind.GPO
	
	def sam(self) -> str:
		return self.label.split("@")[0].lower() # should we lower?

	@property
	def distinguished_name(self) -> str:
		return self.properties.get("distinguishedname") or self.properties.get("dn") or ""