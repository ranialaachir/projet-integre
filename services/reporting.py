# services/reporting.py

from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from .console import console 
from entities.node import Node
from entities.edge import Edge
from entities.path import Path
from entities.node_kind import NodeKind
from entities.edge_kind import EdgeKind

from .formatting import (
    format_path,
    EDGE_META,
    EDGE_SEVERITY,
    DEFAULT_EDGE_META,
    _worst_edge,
)

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