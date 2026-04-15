from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from entities.edge import Edge
    from entities.node import Node

from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind


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

def score_node_as_source(node: "Node", owned_sids: set[str]) -> int:
    """Score optimisé avec détection dynamique des compromissions."""
    props = node.properties or {}
    
    # CRITÈRE 1 : Si le node est dans la liste API 'Owned' -> Score Maximum
    if node.objectid in owned_sids or props.get("owned"):
        return 100 

    score = 0
    # CRITÈRE 2 : Propriétés offensives
    if props.get("hasspn") or props.get("kerberoastable"):
        score += 40
    if props.get("dontreqpreauth"):
        score += 35
    if props.get("admincount"):
        score += 20
    if node.kind == NodeKind.COMPUTER and props.get("hasSession"):
        score += 15

    # Malus pour les comptes inactifs
    if not props.get("enabled", True):
        score -= 100 
        
    return max(0, score)


def score_node_as_target(node: "Node", tier_zero_sids: set[str]) -> int:
    """Score optimisé avec détection dynamique du Tier Zero via l'API."""
    props = node.properties or {}
    
    if not props.get("enabled", True):
        return 0

    # CRITÈRE 1 : Tier Zero dynamique (API)
    if node.objectid in tier_zero_sids:
        return 100

    # CRITÈRE 2 : High Value (Propriété statique/Neo4j)
    if props.get("highvalue"):
        return 90

    # CRITÈRE 3 : Hiérarchie structurelle (fallback)
    hierarchy = {
        NodeKind.DOMAIN: 60,
        NodeKind.GROUP: 55,
        NodeKind.COMPUTER: 40,
        NodeKind.GPO: 30,
        NodeKind.OU: 20
    }
    return hierarchy.get(node.kind, 0)


def score_edge(edge: "Edge") -> int:
    """Score un edge selon sa criticité dans un chemin d'attaque."""
    return EDGE_SEVERITY.get(edge.kind, 0)


# ---------------------------------------------------------------------------
# Prioritization
# ---------------------------------------------------------------------------

def rank_sources(nodes: list["Node"], owned_sids: set[str]) -> list["Node"]:
    relevant_kinds = (NodeKind.USER, NodeKind.COMPUTER)
    scored = [
        (n, score_node_as_source(n, owned_sids))
        for n in nodes
        if n.kind in relevant_kinds
    ]
    scored = [(n, s) for n, s in scored if s > 0]
    scored.sort(key=lambda x: (x[1], x[0].label), reverse=True)
    return [n for n, _ in scored]


def rank_targets(nodes: list["Node"], tier_zero_sids: set[str]) -> list["Node"]:
    scored = [(n, score_node_as_target(n, tier_zero_sids)) for n in nodes]
    scored = [(n, s) for n, s in scored if s > 0]
    scored.sort(key=lambda x: (x[1], x[0].label), reverse=True)
    return [n for n, _ in scored]


def rank_edges(edges: list["Edge"]) -> list["Edge"]:
    scored = [(e, score_edge(e)) for e in edges]
    scored = [(e, s) for e, s in scored if s > 0]
    scored.sort(key=lambda x: (x[1], x[0].kind.value), reverse=True)
    return [e for e, _ in scored]


def prioritize(nodes: list["Node"], edges: list["Edge"] | None = None, owned_sids: set[str] | None = None, tier_zero_sids: set[str] | None = None) -> dict:
    if owned_sids is None:
        owned_sids = set()
    if tier_zero_sids is None:
        tier_zero_sids = set()
    result = {
        "source_nodes": rank_sources(nodes, owned_sids),
        "target_nodes": rank_targets(nodes, tier_zero_sids),
    }
    if edges is not None:
        result["edges"] = rank_edges(edges)
    return result
