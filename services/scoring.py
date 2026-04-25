# services/scoring.py
from entities.edge import Edge
from entities.edge_kind import EdgeKind
from entities.path import Path


# COST, not severity. Lower = easier to exploit = better for attacker.
EDGE_COST: dict[EdgeKind, int] = {
    EdgeKind.GENERIC_ALL:         1,   # full control, trivial
    EdgeKind.OWNS:                1,
    EdgeKind.DCSYNC:              1,   # instant domain compromise
    EdgeKind.GET_CHANGES_ALL:     2,
    EdgeKind.GET_CHANGES:         2,
    EdgeKind.ADMIN_TO:            2,
    EdgeKind.COERCE_TO_TGT:       3,
    EdgeKind.GENERIC_WRITE:       3,
    EdgeKind.ADD_MEMBER:          3,
    EdgeKind.WRITE_DACL:          4,
    EdgeKind.WRITE_OWNER:         4,
    EdgeKind.KERBEROASTABLE:      6,   # requires cracking, takes time
    EdgeKind.ALLOWED_TO_DELEGATE: 7,
    EdgeKind.HAS_SESSION:         8,   # need to be on the machine
    EdgeKind.MEMBER_OF:           9,   # not an attack, just a relationship
    EdgeKind.CONTAINS:            9,
}

DEFAULT_COST = 10


def edge_cost(edge: Edge) -> int:
    return EDGE_COST.get(edge.kind, DEFAULT_COST)


def path_cost(edges: list[Edge]) -> int:
    """Total cost of a path. Lower = better."""
    return sum(edge_cost(e) for e in edges)

def most_critical_edge(path: Path) -> Edge | None:
    """
    Returns the single most dangerous edge in the path.
    Useful for reporting: 'what is the scariest step?'
    Note: use path_cost() for comparing paths, not this.
    """
    if not path.edges:
        return None
    return max(path.edges, key=lambda e: EDGE_COST.get(e.kind, DEFAULT_COST))