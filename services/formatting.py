# services/formatting.py

from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from entities.node import Node
from entities.edge import Edge
from entities.path import Path
from entities.node_kind import NodeKind
from entities.edge_kind import EdgeKind

# TODO : Add these to a different file (utils, entities or services) in v2 if you add a config system.
# ─── Color maps ───────────────────────────────────────────────────────────────

NODE_COLORS: dict[NodeKind, str] = { # TODO: utils:color_maps
    NodeKind.USER:      "#17E625",
    NodeKind.OU:        "#FFAA00",
    NodeKind.GROUP:     "#DBE617",
    NodeKind.GPO:       "#776FC2",
    NodeKind.DOMAIN:    "#17E6B9",
    NodeKind.CONTAINER: "#F79A78",
    NodeKind.COMPUTER:  "#E67873",
}

EDGE_META: dict[EdgeKind, dict] = { # TODO: utils:color_maps

    # ── Structural / low severity ──────────────────────────────────────────
    EdgeKind.MEMBER_OF:           {
        "color": "grey50",
        "icon":  "○",
        "label": "MemberOf — group membership"
    },
    EdgeKind.CONTAINS:            {
        "color": "grey50",
        "icon":  "⊃",
        "label": "Contains — OU contains object"
    },
    EdgeKind.TRUSTED_BY:          {
        "color": "blue",
        "icon":  "⇌",
        "label": "TrustedBy — domain trust"
    },

    # ── Session / presence ─────────────────────────────────────────────────
    EdgeKind.HAS_SESSION:         {
        "color": "yellow",
        "icon":  "◈",
        "label": "HasSession — active session on host"
    },

    # ── Remote access ──────────────────────────────────────────────────────
    EdgeKind.CAN_RDP_TO:          {
        "color": "yellow",
        "icon":  "⬡",
        "label": "CanRDPTo — RDP access"
    },
    EdgeKind.CAN_PS_REMOTE_TO:    {
        "color": "yellow",
        "icon":  "⬡",
        "label": "CanPSRemoteTo — WinRM/PSRemote access"
    },

    # ── Admin access ───────────────────────────────────────────────────────
    EdgeKind.ADMIN_TO:            {
        "color": "red",
        "icon":  "★",
        "label": "AdminTo — local administrator"
    },

    # ── Write primitives ───────────────────────────────────────────────────
    EdgeKind.GENERIC_WRITE:       {
        "color": "bright_yellow",
        "icon":  "✎",
        "label": "GenericWrite — write any non-protected attribute"
    },
    EdgeKind.WRITE_DACL:          {
        "color": "bright_yellow",
        "icon":  "✎",
        "label": "WriteDacl — modify object ACL"
    },
    EdgeKind.WRITE_OWNER:         {
        "color": "bright_yellow",
        "icon":  "✎",
        "label": "WriteOwner — change object owner"
    },
    EdgeKind.ADD_MEMBER:          {
        "color": "bright_yellow",
        "icon":  "✎",
        "label": "AddMember — add user to group"
    },

    # ── Ownership / full control ───────────────────────────────────────────
    EdgeKind.OWNS:                {
        "color": "bright_red",
        "icon":  "⚑",
        "label": "Owns — owner of object (implicit WriteDacl)"
    },
    EdgeKind.GENERIC_ALL:         {
        "color": "bright_red",
        "icon":  "⚑",
        "label": "GenericAll — full control"
    },

    # ── Credential access ──────────────────────────────────────────────────
    EdgeKind.FORCE_CHANGE_PW:     {
        "color": "bright_yellow",
        "icon":  "🔑",
        "label": "ForceChangePassword — reset password without knowing current"
    },
    EdgeKind.READ_LAPS_PASS:      {
        "color": "magenta",
        "icon":  "🔑",
        "label": "ReadLAPSPassword — read local admin password"
    },
    EdgeKind.KERBEROASTABLE:      {
        "color": "bright_magenta",
        "icon":  "⚡",
        "label": "Kerberoastable — SPN set, hash crackable offline"
    },

    # ── Delegation / impersonation ─────────────────────────────────────────
    EdgeKind.ALLOWED_TO_DELEGATE: {
        "color": "magenta",
        "icon":  "⇒",
        "label": "AllowedToDelegate — constrained delegation"
    },
    EdgeKind.ALLOWED_TO_ACT:      {
        "color": "bright_magenta",
        "icon":  "⇒",
        "label": "AllowedToAct — RBCD, impersonate any user to target"
    },

    # ── Coercion ───────────────────────────────────────────────────────────
    EdgeKind.COERCE_TO_TGT:       {
        "color": "bright_red",
        "icon":  "⚡",
        "label": "CoerceToTGT — force TGT via coercion"
    },

    # ── Replication / DCSync ───────────────────────────────────────────────
    EdgeKind.GET_CHANGES:         {
        "color": "yellow",
        "icon":  "↻",
        "label": "GetChanges — partial replication right"
    },
    EdgeKind.GET_CHANGES_ALL:     {
        "color": "bright_red",
        "icon":  "↻",
        "label": "GetChangesAll — full DCSync capable"
    },
    EdgeKind.DCSYNC:              {
        "color": "bold red",
        "icon":  "☠",
        "label": "DCSync — dump all domain hashes"
    },
}

DEFAULT_NODE_COLOR = "white"
DEFAULT_EDGE_META  = {"color": "white", "icon": "→", "label": "edge inconnu"}

# TEMP — will move to services/scoring.py
# See TODO:SCORING tag
# ✅ Correct values — consistent with EDGE_META threat levels
EDGE_SEVERITY: dict[EdgeKind, int] = {              #TODO:scoring
    # ── Structural ────────────────────────────────
    EdgeKind.MEMBER_OF           : 1,
    EdgeKind.CONTAINS            : 1,
    EdgeKind.TRUSTED_BY          : 1,   # info, but monitor for forest trusts

    # ── Presence / remote access ──────────────────
    EdgeKind.HAS_SESSION         : 2,
    EdgeKind.CAN_RDP_TO          : 2,
    EdgeKind.CAN_PS_REMOTE_TO    : 2,

    # ── Delegation ────────────────────────────────
    EdgeKind.ALLOWED_TO_DELEGATE : 3,

    # ── Credential offline ────────────────────────
    EdgeKind.KERBEROASTABLE      : 4,

    # ── Write primitives ──────────────────────────
    EdgeKind.FORCE_CHANGE_PW     : 5,
    EdgeKind.WRITE_DACL          : 5,
    EdgeKind.WRITE_OWNER         : 5,

    # ── Stronger write primitives ─────────────────
    EdgeKind.ADD_MEMBER          : 6,
    EdgeKind.GENERIC_WRITE       : 6,
    EdgeKind.READ_LAPS_PASS      : 6,

    # ── Admin / ownership ─────────────────────────
    EdgeKind.ADMIN_TO            : 7,
    EdgeKind.OWNS                : 7,

    # ── High impact ───────────────────────────────
    EdgeKind.ALLOWED_TO_ACT      : 8,   # RBCD → full impersonation
    EdgeKind.COERCE_TO_TGT       : 8,
    EdgeKind.GENERIC_ALL         : 8,
    EdgeKind.GET_CHANGES         : 8,

    # ── DCSync path ───────────────────────────────
    EdgeKind.GET_CHANGES_ALL     : 9,

    # ── Critical ──────────────────────────────────
    EdgeKind.DCSYNC              : 10,
}

# TODO:SCORING — migrate to services/scoring.py when ready
def _worst_edge(path: Path) -> Edge | None: # TODO:SCORING
    """Retourne l'edge la plus critique du path (selon EDGE_SEVERITY)."""
    if not path.edges:
        return None
    return max(
        path.edges,
        key=lambda e: EDGE_SEVERITY.get(e.kind, 0)
    )

def format_node(node: Node, tag:str="") -> Text:  # TODO : format the tag better
    """
    Retourne un Text rich :  [USER] JOFFREY@SEVENKINGDOMS.LOCAL
    node.kind est un NodeKind enum → on utilise .value pour le display.
    """
    color      = NODE_COLORS.get(node.kind, DEFAULT_NODE_COLOR)
    kind_str  = node.kind.value  # "User", "Group", etc.

    t = Text()
    t.append(f"\n{tag} [{kind_str}]", style=f"bold {color}")
    t.append(f" {node.objectid}",  style=color)
    t.append(f" - {node.label}",  style=color)
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
    t.append(f"\n  {icon} ",         style=color)
    t.append(f"──[{kind_str}]──▶ ", style=f"bold {color}")
    t.append(f"({label})",           style=f"italic {color}")
    return t

def format_path(path: Path, index: int = 1) -> Panel:
    """
    Formate un Path complet comme un Panel rich.
    Entrelace les nœuds et les edges dans l'ordre.
    """
    worst    = _worst_edge(path)
    severity = EDGE_SEVERITY.get(worst.kind, 0) if worst else 0

    # Couleur de la bordure selon la criticité du pire edge
    # TODO : Change after Scoring, scoring should give us an enum of severity
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