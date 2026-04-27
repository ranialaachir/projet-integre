# repositories/strategy_runner_repository.py

from dataclasses import dataclass
from entities.exploit_result import ExploitResult
from entities.edge import Edge
from exceptions.hop_failed_error import HopFailedError
from services.parse_objects import parse_dict_node, parse_list_edge
from .base_repository import BaseRepository, CREDS
from .acting_principal_repository import ActingPrincipalResolver, PrincipalResolution


@dataclass
class StrategyTestResult:
    relationship:  str
    strategy_name: str
    edge:          Edge | None          = None
    result:        ExploitResult | None = None
    error:         str | None           = None
    skipped:       bool                 = False
    skip_reason:   str                  = ""

    @property
    def success(self) -> bool:
        return self.result is not None and self.result.success is True


class StrategyRunnerRepository(BaseRepository):

    def __init__(self):
        super().__init__()
        self._resolver = ActingPrincipalResolver()

    # ── Query ────────────────────────────────────────────────────────────────

    def query_edges_for_relationship(
        self,
        relationship: str,
        limit: int = 3,
        src_label: str = "Base",
        dst_label: str = "Base",
    ) -> tuple[dict, list]:
        cypher = {
            "query": (
                f"MATCH p=(:{src_label})-[:{relationship}]->(:{dst_label})\n"
                f"RETURN p\n"
                f"LIMIT {limit}"
            ),
            "include_properties": True,
        }
        raw = self.bh_request.bh_post("/api/v2/graphs/cypher", cypher)
        if not raw or "data" not in raw:
            return {}, []

        nodes = raw["data"].get("nodes", {})
        edges = raw["data"].get("edges", [])
        return nodes, edges

    # ── Resolution ───────────────────────────────────────────────────────────

    def _resolve(self, edge: Edge) -> PrincipalResolution:
        """
        Try to find a usable logon principal for edge.source_node.
        Handles User, Computer, and Group (recursive member lookup).
        """
        return self._resolver.resolve(edge.source_node, CREDS)

    # ── Main runner ──────────────────────────────────────────────────────────

    def run_single_strategy(
        self,
        strategy_cls,
        relationship: str,
        src_label:    str  = "Base",
        dst_label:    str  = "Base",
        limit:        int  = 3,
        dry_run:      bool = False,
    ) -> list[StrategyTestResult]:

        results       = []
        strategy_name = strategy_cls.__name__

        # ── Query BloodHound ─────────────────────────────────────────────────
        raw_nodes, raw_edges = self.query_edges_for_relationship(
            relationship, limit, src_label, dst_label
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

            # ── Resolve acting principal (User / Computer / Group member) ────
            resolution = self._resolve(edge)
            if not resolution.ok:
                entry.skipped     = True
                entry.skip_reason = resolution.reason
                results.append(entry)
                continue

            # ── Strategy sanity check ────────────────────────────────────────
            strategy = strategy_cls(edge=edge)
            if not strategy.can_exploit():
                entry.skipped     = True
                entry.skip_reason = (
                    f"can_exploit() → False for "
                    f"{edge.source_node.label} → {edge.goal_node.label}"
                )
                results.append(entry)
                continue

            # ── Dry-run ──────────────────────────────────────────────────────
            if dry_run:
                entry.skipped     = True
                entry.skip_reason = "Dry run"
                results.append(entry)
                continue

            # ── Exploit ──────────────────────────────────────────────────────
            try:
                entry.result = strategy.exploit(resolution.creds)
            except HopFailedError as exc:
                entry.error = str(exc)
            except Exception as exc:
                entry.error = f"Unexpected error: {exc}"

            results.append(entry)

        return results