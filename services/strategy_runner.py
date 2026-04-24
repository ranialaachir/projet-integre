# services/strategy_runner.py
from dataclasses import dataclass, field
from entities.exploit_result import ExploitResult
from entities.edge import Edge
from exceptions.hop_failed_error import HopFailedError
from .parse_objects import parse_dict_node, parse_list_edge


@dataclass
class StrategyTestResult:
    relationship:   str
    strategy_name:  str
    edge:           Edge | None          = None
    result:         ExploitResult | None = None
    error:          str | None           = None
    skipped:        bool                 = False
    skip_reason:    str                  = ""

    @property
    def success(self) -> bool:
        return self.result is not None and self.result.success is True


def query_edges_for_relationship(
    bh,
    relationship: str,
    limit: int = 3,
    src_label: str = "Base",
    dst_label: str = "Base",
) -> tuple[dict, list]:
    """
    Query BloodHound CE API using the path-return format.
    """
    cypher = {
        "query": (
            f"MATCH p=(:{src_label})-[:{relationship}]->(:{dst_label})\n"
            f"RETURN p\n"
            f"LIMIT {limit}"
        ),
        "include_properties": True,
    }

    raw = bh.bh_post("/api/v2/graphs/cypher", cypher)
    if not raw or "data" not in raw:
        return {}, []

    nodes = raw["data"].get("nodes", {})
    edges = raw["data"].get("edges", [])
    return nodes, edges


def run_single_strategy(
    bh,
    strategy_cls,
    relationship: str,
    creds: dict,
    src_label: str = "Base",
    dst_label: str = "Base",
    limit: int = 3,
    dry_run: bool = False,
) -> list[StrategyTestResult]:
    results = []
    strategy_name = strategy_cls.__name__

    # ── Query Neo4j ──────────────────────────────────────────────────────
    raw_nodes, raw_edges = query_edges_for_relationship(
        bh, relationship, limit, src_label, dst_label
    )

    if not raw_edges or not raw_nodes:
        results.append(StrategyTestResult(
            relationship=relationship,
            strategy_name=strategy_name,
            skipped=True,
            skip_reason=f"No {relationship} edge found in the graph",
        ))
        return results

    # ── Parse ────────────────────────────────────────────────────────────
    nodes = parse_dict_node(n=raw_nodes)
    edges = parse_list_edge(e=raw_edges, nodes=nodes)

    # ── Run each edge ────────────────────────────────────────────────────
    for edge in edges:
        entry = StrategyTestResult(
            relationship=relationship,
            strategy_name=strategy_name,
            edge=edge,
        )

        strategy = strategy_cls(edge=edge)

        if not strategy.can_exploit():
            entry.skipped = True
            entry.skip_reason = (
                f"can_exploit() returned False for "
                f"{edge.source_node.label} → {edge.goal_node.label}"
            )
            results.append(entry)
            continue

        if dry_run:
            entry.skipped = True
            entry.skip_reason = "Dry run"
            results.append(entry)
            continue

        try:
            entry.result = strategy.exploit(creds)
        except HopFailedError as exc:
            entry.error = str(exc)
        except Exception as exc:
            entry.error = f"Unexpected error: {exc}"

        results.append(entry)

    return results