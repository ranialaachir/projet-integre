# entities/path.py

from dataclasses import dataclass, field
from typing import List
from .node import Node
from .edge import Edge


@dataclass
class Path:
    source_node: Node
    goal_node: Node
    edges: List[Edge] = field(default_factory=list)

    @property
    def length(self) -> int:
        """Number of edges (hops) in the path"""
        return len(self.edges)

    @property
    def start(self) -> Node:
        """Starting node of the path"""
        return self.source_node

    @property
    def end(self) -> Node:
        """Final node of the path"""
        return self.goal_node

    def node_sequence(self) -> List[Node]:
        """
        Returns the full sequence of nodes from start to end.
        Example: UserA -> GroupX -> ComputerB
        """
        if not self.edges:
            return [self.source_node]

        nodes: List[Node] = [self.source_node]

        for edge in self.edges:
            nodes.append(edge.goal_node)

        return nodes

    def edge_sequence(self) -> List[Edge]:
        return self.edges

    def __str__(self) -> str:
        return f"Path: {self.source_node} → ... → {self.goal_node}  ({self.length} hops)"

    def __repr__(self) -> str:
        return f"Path({self.source_node.label} → {self.goal_node.label}, edges={self.length})"