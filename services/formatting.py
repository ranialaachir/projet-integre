# services/formatting.py

from rich.panel import Panel
from rich.text import Text
from rich.style import Style

from entities.node import Node
from entities.edge import Edge
from entities.path import Path
from .scoring import path_cost, edge_cost  # added edge_cost for per‑edge display
from references.privilege_levels import PrivilegeLevel
from references.color_maps import NODE_COLORS, EDGE_META, DEFAULT_NODE_COLOR, DEFAULT_EDGE_META


def format_node(node: Node, tag: str = "") -> Text:
    """Return rich Text:  [USER] JOFFREY@SEVENKINGDOMS.LOCAL"""
    color = NODE_COLORS.get(node.kind, DEFAULT_NODE_COLOR)
    kind_str = node.kind.value

    t = Text()
    if tag:
        t.append(f"{tag} ", style="dim")
    t.append(f"[{kind_str}]", style=f"bold {color}")
    t.append(f" {node.label}", style=color)
    return t


def format_edge(edge: Edge) -> Text:
    """Return rich Text:    ⚡ ──[HasSPNConfigured]──▶  (Kerberoast …)  [cost: 6]"""
    meta = EDGE_META.get(edge.kind, DEFAULT_EDGE_META)
    color = meta["color"]
    icon = meta["icon"]
    label = meta["label"]
    kind_str = edge.kind.value

    cost = edge_cost(edge)

    t = Text()
    t.append(f"\n  {icon} ", style=color)
    t.append(f"──[{kind_str}]──▶ ", style=f"bold {color}")
    t.append(f"({label})", style=f"italic {color}")
    t.append(f"  [cost: {cost}]", style="dim white")
    return t


def format_path(
    path: Path,
    index: int = 1,
    privilege_level: PrivilegeLevel | None = None
) -> Panel:
    """
    Return a nicely formatted Panel showing the attack path step by step.
    """
    cost = path_cost(path.edges)

    # Determine border color based on target privilege level
    if privilege_level is not None:
        if privilege_level <= PrivilegeLevel.DOMAIN_ADMIN:
            border_style = "bold red"
        elif privilege_level <= PrivilegeLevel.SERVER_ADMIN:
            border_style = "yellow"
        elif privilege_level <= PrivilegeLevel.DELEGATED_ADMIN:
            border_style = "bright_yellow"
        else:
            border_style = "blue"
    else:
        border_style = "white"

    # Build the panel title (metadata line)
    title_parts = Text()
    title_parts.append(f"Path #{index}", style="bold white")
    title_parts.append(f"  —  {path.length} hop(s)", style="dim")
    title_parts.append(f"  —  cost: {cost}", style="dim")
    if privilege_level is not None:
        title_parts.append(
            f"  —  target tier: {privilege_level.name}",
            style=f"bold {border_style}"
        )

    # Build the inside content, interleaving nodes and edges
    content = Text()
    nodes = path.node_sequence()

    for i, node in enumerate(nodes):
        # Print the node (indented a bit)
        content.append("\n  ")
        content.append_text(format_node(node))

        # Print the edge that leads to the next node (if any)
        if i < len(path.edges):
            content.append_text(format_edge(path.edges[i]))

    # Wrap everything in a Panel with the title
    panel = Panel(
        content,
        title=title_parts,
        border_style=border_style,
        padding=(1, 2),
        subtitle=f"From {path.source_node.label}  →  {path.goal_node.label}"
    )
    return panel