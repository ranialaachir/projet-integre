# services/strategy_runner.py
from dataclasses import dataclass
from entities.exploit_result import ExploitResult
from entities.edge import Edge
from entities.node_kind import NodeKind
from exceptions.hop_failed_error import HopFailedError
from services.parse_objects import parse_dict_node, parse_list_edge
from references.cred_store import KNOWN_SECRETS
from .base_repository import BaseRepository
from .base_repository import CREDS

# ── Node kinds that can actually authenticate ────────────────────────────────
LOGON_KINDS = {NodeKind.USER, NodeKind.COMPUTER}

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

class StrategyRunnerRepository(BaseRepository):
    def query_edges_for_relationship( 
        self, relationship: str, limit: int = 3,
        src_label: str = "Base", dst_label: str = "Base",
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


    def _attacker_sam(self,edge: Edge) -> str:
        """Normalised SAM of the source node, same logic as Node.sam()."""
        return edge.source_node.sam().lower().split("@")[0]


    def _check_attacker(self,edge: Edge) -> str | None:
        """
        Return a skip-reason string if we cannot use this attacker,
        or None if everything looks fine.
        """
        attacker = edge.source_node

        # ── 1. Must be a logon-capable node kind ────────────────────────────
        if attacker.kind not in LOGON_KINDS:
            return (
                f"Source '{attacker.label}' is {attacker.kind.value} "
                f"— not a logon principal."
            )

        # ── 2. Must have known credentials ──────────────────────────────────
        sam = self._attacker_sam(edge)
        if sam not in KNOWN_SECRETS:
            return (
                f"No credentials known for '{sam}'. "
                f"Add them to cred_store.KNOWN_SECRETS to exploit this edge."
            )

        return None   # all good


    def run_single_strategy(
        self, strategy_cls,
        relationship: str,
        src_label: str = "Base",
        dst_label: str = "Base",
        limit: int = 3,
        dry_run: bool = False,
    ) -> list[StrategyTestResult]:
        results      = []
        strategy_name = strategy_cls.__name__

        # ── Query BloodHound CE ──────────────────────────────────────────────
        raw_nodes, raw_edges = self.query_edges_for_relationship(
            self.bh_request, relationship, limit, src_label, dst_label
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

            # ── Pre-flight: can we even authenticate as the attacker? ────────
            skip_reason = self._check_attacker(edge)
            if skip_reason:
                entry.skipped    = True
                entry.skip_reason = skip_reason
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

            # ── Dry-run mode ─────────────────────────────────────────────────
            if dry_run:
                entry.skipped     = True
                entry.skip_reason = "Dry run"
                results.append(entry)
                continue

            # ── Actually exploit ─────────────────────────────────────────────
            try:
                entry.result = strategy.exploit(CREDS)
            except HopFailedError as exc:
                entry.error = str(exc)
            except Exception as exc:
                entry.error = f"Unexpected error: {exc}"

            results.append(entry)

        return results