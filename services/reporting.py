# services/reporting.py

from rich.table import Table
from rich import box

from references.privilege_levels import PrivilegeLevel

from .console import console
from .formatting import format_path
from references.color_maps import EDGE_META, DEFAULT_EDGE_META
from .scoring import  most_critical_edge


def _tier_color(level: PrivilegeLevel) -> str:
    if level <= PrivilegeLevel.DOMAIN_ADMIN:
        return "bold red"
    elif level <= PrivilegeLevel.SERVER_ADMIN:
        return "yellow"
    elif level <= PrivilegeLevel.DELEGATED_ADMIN:
        return "bright_yellow"
    return "white"


def _cost_color(cost: int) -> str:
    if cost <= 5:
        return "red"       # cheap = easy = dangerous
    elif cost <= 15:
        return "yellow"
    return "green"         # expensive = hard = less urgent


def print_report(
    results: list[dict],       # {"path", "privilege_level", "source", "target", "cost"}
    domain: str = "SEVENKINGDOMS.LOCAL"
) -> None:
    """
    Main report entry point.
    Displays: header → summary table → detailed panels.

    results must be pre-sorted by (privilege_level, cost) before calling.
    """
    console.rule(f"[bold red]BloodHound Report — {domain}[/]")
    console.print(f"  [dim]{len(results)} attack path(s) found[/]\n")

    if not results:
        console.print("[green]  No paths found.[/]")
        return

    # ── Summary table ─────────────────────────────────────────────────────────
    table = Table(
        title="Attack Paths Summary",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("#",            style="dim",           width=4)
    table.add_column("Source",       style="cyan",          min_width=30)
    table.add_column("Target",       style="bright_red",    min_width=30)
    table.add_column("Tier",         style="white",         width=16,  justify="center")
    table.add_column("Hops",         style="white",         width=6,   justify="center")
    table.add_column("Cost",         style="white",         width=8,   justify="center")
    table.add_column("Worst Edge",   style="bright_yellow", min_width=20)

    for i, r in enumerate(results, 1):
        path  = r["path"]
        level = r["privilege_level"]
        cost  = r["cost"]

        worst       = most_critical_edge(path)
        worst_label = (
            EDGE_META.get(worst.kind, DEFAULT_EDGE_META)["label"]
            if worst else "—"
        )

        tier_color = _tier_color(level)
        cost_color = _cost_color(cost)

        table.add_row(
            str(i),
            r["source"].label,
            r["target"].label,
            f"[{tier_color}]{level.name}[/{tier_color}]",
            str(path.length),
            f"[{cost_color}]{cost}[/{cost_color}]",
            worst_label,
        )

    console.print(table)
    console.print()

    # ── Detailed panels ───────────────────────────────────────────────────────
    for i, r in enumerate(results, 1):
        console.print(format_path(
            path=r["path"],
            index=i,
            privilege_level=r["privilege_level"],
        ))
        console.print()

    console.rule("[dim]End of report[/]")