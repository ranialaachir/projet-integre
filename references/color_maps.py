# references/color_maps.py

from entities.node_kind import NodeKind
from entities.edge_kind import EdgeKind

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
