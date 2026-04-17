from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from entities.edge import Edge
    from entities.node import Node

from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind
from utils.request import BHRequest
from utils.bh_api_manager import BHAPIManager


EDGE_SEVERITY: dict[EdgeKind, int] = {
    EdgeKind.MEMBER_OF:           1,
    EdgeKind.CONTAINS:            1,
    EdgeKind.HAS_SESSION:         2,
    EdgeKind.ALLOWED_TO_DELEGATE: 3,
    EdgeKind.KERBEROASTABLE:      4,
    EdgeKind.WRITE_DACL:          5,
    EdgeKind.WRITE_OWNER:         5,
    EdgeKind.GENERIC_WRITE:       6,
    EdgeKind.ADD_MEMBER:          6,
    EdgeKind.ADMIN_TO:            7,
    EdgeKind.OWNS:                7,
    EdgeKind.GENERIC_ALL:         8,
    EdgeKind.COERCE_TO_TGT:       8,
    EdgeKind.GET_CHANGES:         8,
    EdgeKind.GET_CHANGES_ALL:     9,
    EdgeKind.DCSYNC:              10,
}


def score_node_as_source(node: "Node", owned_sids: set[str]) -> int:
    props = node.properties or {}

    if node.objectid in owned_sids or props.get("owned"):
        return 100

    score = 0
    if props.get("hasspn") or props.get("kerberoastable"):
        score += 40
    if props.get("dontreqpreauth"):
        score += 35
    if props.get("admincount"):
        score += 20
    if not props.get("enabled", True):
        return 0

    return score


def score_node_as_target(node: "Node", tier_zero_sids: set[str]) -> int:
    props = node.properties or {}

    if node.objectid in tier_zero_sids:
        return 100
    if props.get("highvalue"):
        return 90

    return {
        NodeKind.DOMAIN:    60,
        NodeKind.GROUP:     55,
        NodeKind.COMPUTER:  40,
        NodeKind.GPO:       30,
        NodeKind.OU:        20,
    }.get(node.kind, 0)


def score_edge(edge: "Edge") -> int:
    return EDGE_SEVERITY.get(edge.kind, 0)


def prioritize(
    nodes: list["Node"],
    bh_request: BHRequest,
    limit_sources: int = 20,
    limit_targets: int = 5,
    edges: list["Edge"] | None = None,
) -> dict:
    # 1. Récupération du contexte API
    try:
        api = BHAPIManager(bh_request)
        owned_sids    = api.get_owned_sids()
        tier_zero_sids = api.get_tier_zero_sids()
        print(f"[+] Owned : {len(owned_sids)} | Tier Zero : {len(tier_zero_sids)}")
    except Exception:
        owned_sids     = set()
        tier_zero_sids = set()
        print("[!] API context unavailable, scoring on properties only")

    # 2. Scorer et trier les sources (USER et COMPUTER uniquement)
    sources = sorted(
        [n for n in nodes if n.kind in (NodeKind.USER, NodeKind.COMPUTER)],
        key=lambda n: score_node_as_source(n, owned_sids),
        reverse=True
    )
    sources = [n for n in sources if score_node_as_source(n, owned_sids) > 0]

    # 3. Scorer et trier les cibles
    targets = sorted(
        nodes,
        key=lambda n: score_node_as_target(n, tier_zero_sids),
        reverse=True
    )
    targets = [n for n in targets if score_node_as_target(n, tier_zero_sids) > 0]

    # 4. Résultat
    result = {
        "source_nodes": sources[:limit_sources],
        "target_nodes": targets[:limit_targets],
    }
    if edges:
        result["edges"] = sorted(edges, key=score_edge, reverse=True)

    return result