# services/reporting.py

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from entities.node import Node
from entities.edge import Edge
from entities.path import Path
from entities.node_kind import NodeKind
from entities.edge_kind import EdgeKind

console = Console()


# ─── Color maps ───────────────────────────────────────────────────────────────

NODE_COLORS: dict[NodeKind, str] = {
    NodeKind.USER:      "cyan",
    NodeKind.GROUP:     "bright_blue",
    NodeKind.COMPUTER:  "yellow",
    NodeKind.DOMAIN:    "bright_red",
    NodeKind.GPO:       "magenta",
    NodeKind.OU:        "green",
    NodeKind.CONTAINER: "dim white",
}

EDGE_META: dict[EdgeKind, dict] = {
    EdgeKind.MEMBER_OF:          {"color": "dim",            "icon": "○", "label": "MemberOf"},
    EdgeKind.HAS_SESSION:        {"color": "yellow",         "icon": "◈", "label": "HasSession → session active"},
    EdgeKind.ADMIN_TO:           {"color": "red",            "icon": "★", "label": "AdminTo → local admin"},
    EdgeKind.GENERIC_WRITE:      {"color": "bright_yellow",  "icon": "✎", "label": "GenericWrite → modifier l'objet"},
    EdgeKind.GENERIC_ALL:        {"color": "bright_red",     "icon": "⚑", "label": "GenericAll → contrôle total"},
    EdgeKind.WRITE_DACL:         {"color": "bright_yellow",  "icon": "✎", "label": "WriteDacl → modifier les ACL"},
    EdgeKind.WRITE_OWNER:        {"color": "bright_yellow",  "icon": "✎", "label": "WriteOwner → changer le owner"},
    EdgeKind.DCSYNC:             {"color": "red bold",       "icon": "☠", "label": "DCSync → dump tous les hashes"},
    EdgeKind.GET_CHANGES:        {"color": "yellow",         "icon": "↻", "label": "GetChanges (DCSync partiel)"},
    EdgeKind.GET_CHANGES_ALL:    {"color": "bright_red",     "icon": "↻", "label": "GetChangesAll → DCSync complet"},
    EdgeKind.KERBEROASTABLE:     {"color": "bright_magenta", "icon": "⚡", "label": "Kerberoast → crack hash offline"},
    EdgeKind.ALLOWED_TO_DELEGATE:{"color": "magenta",        "icon": "⇒", "label": "AllowedToDelegate → usurpation"},
    EdgeKind.OWNS:               {"color": "bright_red",     "icon": "⚑", "label": "Owns → propriétaire de l'objet"},
}

DEFAULT_NODE_COLOR = "white"
DEFAULT_EDGE_META  = {"color": "white", "icon": "→", "label": "edge inconnu"}


# TODO : Criticité pour trier (plus haut = plus critique)
EDGE_SEVERITY: dict[EdgeKind, int] = { # FUNCTION IN SCORING.PY
    EdgeKind.MEMBER_OF: 1,
    EdgeKind.HAS_SESSION: 2,
    EdgeKind.ALLOWED_TO_DELEGATE: 3,
    EdgeKind.KERBEROASTABLE: 4,
    EdgeKind.WRITE_DACL: 5,
    EdgeKind.WRITE_OWNER: 5,
    EdgeKind.GENERIC_WRITE: 6,
    EdgeKind.ADMIN_TO: 7,
    EdgeKind.OWNS: 7,
    EdgeKind.GENERIC_ALL: 8,
    EdgeKind.GET_CHANGES: 8,
    EdgeKind.GET_CHANGES_ALL: 9,
    EdgeKind.DCSYNC: 10,
}

# ─── Helpers internes ─────────────────────────────────────────────────────────

# TODO : Add to scoring
def _worst_edge(path: Path) -> Edge | None:
    """Retourne l'edge la plus critique du path (selon EDGE_SEVERITY)."""
    if not path.edges:
        return None
    return max(
        path.edges,
        key=lambda e: EDGE_SEVERITY.get(e.kind, 0)
    )


# ─── Formatters ───────────────────────────────────────────────────────────────

def format_node(node: Node) -> Text:
    """
    Retourne un Text rich :  [USER] JOFFREY@SEVENKINGDOMS.LOCAL
    node.kind est un NodeKind enum → on utilise .value pour le display.
    """
    color      = NODE_COLORS.get(node.kind, DEFAULT_NODE_COLOR)
    label_str  = node.kind.value  # "User", "Group", etc.

    t = Text()
    t.append(f"[{label_str}]", style=f"bold {color}")
    t.append(f" {node.label}",  style=color)
    return t

def format_edge(edge: Edge) -> Text:
    """
    Retourne :    ⚡ ──[HasSPNConfigured]──▶  (Kerberoast → crack hash offline)
    edge.kind est un EdgeKind enum → on utilise .value pour le label BloodHound.
    """
    meta      = EDGE_META.get(edge.kind, DEFAULT_EDGE_META)
    color     = meta["color"]
    icon      = meta["icon"]
    label     = meta["label"]
    kind_str  = edge.kind.value   # "HasSPNConfigured", "DCSync", etc.

    t = Text()
    t.append(f"  {icon} ", style=color)
    t.append(f"──[{kind_str}]──▶ ", style=f"bold {color}")
    t.append(f"({label})",          style=f"italic {color}")
    return t

def format_path(path: Path, index: int = 1) -> Panel:
    """
    Formate un Path complet comme un Panel rich.
    Entrelace les nœuds et les edges dans l'ordre.
    """
    worst    = _worst_edge(path)
    severity = EDGE_SEVERITY.get(worst.kind, 0) if worst else 0

    # Couleur de la bordure selon la criticité du pire edge
    # TODO : Change after Scoring
    if severity >= 8:
        border_color = "bold red"
    elif severity >= 5:
        border_color = "yellow"
    else:
        border_color = "blue"

    content = Text()
    content.append(f"Path #{index}", style="bold white")
    content.append(f"  —  {path.length} hop(s)\n\n", style="dim")

    # nodes = _node_sequence(path)
    nodes = path.node_sequence()

    for i, node in enumerate(nodes):
        content.append_text(format_node(node))
        content.append("\n")

        if i < len(path.edges):
            content.append_text(format_edge(path.edges[i]))
            content.append("\n")

    return Panel(content, border_style=border_color, padding=(0, 2))


# ─── Rapport complet ──────────────────────────────────────────────────────────

def print_report(paths: list[Path], domain: str = "SEVENKINGDOMS.LOCAL") -> None: # TODO : delete default
    """
    Point d'entrée principal.
    Affiche : en-tête → tableau récap → détail Panel par Panel.
    """
    console.rule(f"[bold red]BloodHound Report — {domain}[/]")
    console.print(f"  [dim]{len(paths)} attack path(s) vers Domain Admins[/]\n")

    if not paths:
        console.print("[green]  Aucun chemin trouvé.[/]")
        return

    # ── Tableau récapitulatif ──────────────────────────────────────────────────
    table = Table(
        title="Résumé des attack paths",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("#",          style="dim",          width=4)
    table.add_column("Source",     style="cyan",         min_width=35)
    table.add_column("Target",     style="bright_red",   min_width=35)
    table.add_column("Hops",       style="white",        width=6,  justify="center")
    table.add_column("Pire edge",  style="bright_yellow",min_width=20)
    table.add_column("Criticité",  style="red",          width=10, justify="center")

    for i, path in enumerate(paths, 1):
        worst    = _worst_edge(path)
        severity = EDGE_SEVERITY.get(worst.kind, 0) if worst else 0
        worst_label = (
            EDGE_META.get(worst.kind, DEFAULT_EDGE_META)["label"]
            if worst else "—"
        )

        sev_color = "red" if severity >= 8 else "yellow" if severity >= 5 else "green"

        table.add_row(
            str(i),
            path.source_node.label,
            path.goal_node.label,
            str(path.length),
            worst_label,
            f"[{sev_color}]{severity}/10[/{sev_color}]",
        )

    console.print(table)
    console.print()

    # ── Détail de chaque path ─────────────────────────────────────────────────
    for i, path in enumerate(paths, 1):
        console.print(format_path(path, index=i))
        console.print()

    console.rule("[dim]Fin du rapport[/]")