from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from entities.edge import Edge
    from entities.node import Node

from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind


# ---------------------------------------------------------------------------
# High-value target names (BloodHound CE / GOAD-Mini format)
# ---------------------------------------------------------------------------

HIGH_VALUE_TARGETS = [
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "SCHEMA ADMINS",
    "DOMAIN CONTROLLERS",
    "KRBTGT",
    "ACCOUNT OPERATORS",
    "BACKUP OPERATORS",
]


# ---------------------------------------------------------------------------
# Edge severity scoring
# ---------------------------------------------------------------------------

EDGE_SEVERITY: dict[EdgeKind, int] = {
    EdgeKind.MEMBER_OF:          1,
    EdgeKind.HAS_SESSION:        2,
    EdgeKind.ALLOWED_TO_DELEGATE: 3,
    EdgeKind.KERBEROASTABLE:     4,
    EdgeKind.WRITE_DACL:         5,
    EdgeKind.WRITE_OWNER:        5,
    EdgeKind.GENERIC_WRITE:      6,
    EdgeKind.ADD_MEMBER:         6,
    EdgeKind.ADMIN_TO:           7,
    EdgeKind.OWNS:               7,
    EdgeKind.GENERIC_ALL:        8,
    EdgeKind.COERCE_TO_TGT:      8,
    EdgeKind.GET_CHANGES:        8,
    EdgeKind.GET_CHANGES_ALL:    9,
    EdgeKind.DCSYNC:             10,
    EdgeKind.CONTAINS:           1,
}


# ---------------------------------------------------------------------------
# Core scoring
# ---------------------------------------------------------------------------

def score_node_as_source(node: "Node") -> int:
    """Score a node selon son utilisabilité comme point de départ d'attaque."""
    score = 0
    props = node.properties or {}

    if props.get("owned") or props.get("isOwnedObject"):
        score += 50

    if props.get("hasspn") or props.get("kerberoastable"):
        score += 40

    if props.get("dontreqpreauth"):
        score += 35

    if props.get("admincount"):
        score += 20

    if node.kind == NodeKind.COMPUTER and props.get("hasSession"):
        score += 15

    if not props.get("enabled", True):
        score -= 50

    return score


def score_node_as_target(node: "Node") -> int:
    """Score a node selon sa valeur stratégique comme cible d'attaque."""
    props = node.properties or {}
    label = (node.label or "").upper()

    if not props.get("enabled", True):
        return 0

    for target in HIGH_VALUE_TARGETS:
        if target in label:
            return 100

    if props.get("highvalue"):
        return 90

    if node.kind == NodeKind.USER:
        return 0

    if node.kind == NodeKind.DOMAIN:
        return 60

    if node.kind == NodeKind.GROUP:
        return 55

    if node.kind == NodeKind.COMPUTER:
        return 40

    if node.kind == NodeKind.GPO:
        return 30

    if node.kind == NodeKind.OU:
        return 20

    return 10


def score_edge(edge: "Edge") -> int:
    """Score un edge selon sa criticité dans un chemin d'attaque."""
    return EDGE_SEVERITY.get(edge.kind, 0)


# ---------------------------------------------------------------------------
# Prioritization
# ---------------------------------------------------------------------------

def rank_sources(nodes: list["Node"]) -> list["Node"]:
    relevant_kinds = (NodeKind.USER, NodeKind.COMPUTER)
    scored = [
        (n, score_node_as_source(n))
        for n in nodes
        if n.kind in relevant_kinds
    ]
    scored = [(n, s) for n, s in scored if s > 0]
    scored.sort(key=lambda x: (x[1], x[0].label), reverse=True)
    return [n for n, _ in scored]


def rank_targets(nodes: list["Node"]) -> list["Node"]:
    scored = [(n, score_node_as_target(n)) for n in nodes]
    scored = [(n, s) for n, s in scored if s > 0]
    scored.sort(key=lambda x: (x[1], x[0].label), reverse=True)
    return [n for n, _ in scored]


def rank_edges(edges: list["Edge"]) -> list["Edge"]:
    scored = [(e, score_edge(e)) for e in edges]
    scored = [(e, s) for e, s in scored if s > 0]
    scored.sort(key=lambda x: (x[1], x[0].kind.value), reverse=True)
    return [e for e, _ in scored]


def prioritize(nodes: list["Node"], edges: list["Edge"] | None = None) -> dict:
    result = {
        "source_nodes": rank_sources(nodes),
        "target_nodes": rank_targets(nodes),
    }
    if edges is not None:
        result["edges"] = rank_edges(edges)
    return result
