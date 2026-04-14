# entities/edge.py

from dataclasses import dataclass
from .node import Node
from .edge_kind import EdgeKind


@dataclass(frozen=True) # immutable
class Edge:
    source_node: Node
    goal_node: Node
    kind: EdgeKind

	# aliases
    @property
    def source(self) -> Node:
        return self.source_node

    @property
    def target(self) -> Node:
        return self.goal_node
    
    def __str__(self):
            return f"{self.source} --[{self.kind}]--> {self.target}"