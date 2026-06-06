# references/privilege_levels.py
"""
Static reference for Active Directory privilege levels.
Based on Microsoft's tiered administration model and BloodHound conventions.
"""

from enum import IntEnum
from entities.node import Node

class PrivilegeLevel(IntEnum):
    """
    Standard AD privilege tiers.
    Lower number = more privileged = more valuable target.
    """
    DOMAIN_ADMIN     = 0   # Full domain control (DA, EA, SA, Administrators)
    SERVER_ADMIN     = 1   # Server Operators, Backup Operators, DnsAdmins
    DELEGATED_ADMIN  = 2   # Account Operators, Print Operators
    PRIVILEGED_USER  = 3   # Has admin rights on specific machines
    STANDARD_USER    = 4   # Regular domain user
    GUEST            = 5   # Limited / anonymous


# Well-known SIDs and group names that ALWAYS map to a tier
# (These are Microsoft standards, not arbitrary)
WELL_KNOWN_GROUPS: dict[str, PrivilegeLevel] = {
    "DOMAIN ADMINS":          PrivilegeLevel.DOMAIN_ADMIN,
    "ENTERPRISE ADMINS":      PrivilegeLevel.DOMAIN_ADMIN,
    "SCHEMA ADMINS":          PrivilegeLevel.DOMAIN_ADMIN,
    "ADMINISTRATORS":         PrivilegeLevel.DOMAIN_ADMIN,
    "DOMAIN CONTROLLERS":     PrivilegeLevel.DOMAIN_ADMIN,
    
    "SERVER OPERATORS":       PrivilegeLevel.SERVER_ADMIN,
    "BACKUP OPERATORS":       PrivilegeLevel.SERVER_ADMIN,
    "DNSADMINS":              PrivilegeLevel.SERVER_ADMIN,
    "CERT PUBLISHERS":        PrivilegeLevel.SERVER_ADMIN,
    "KEY ADMINS":             PrivilegeLevel.SERVER_ADMIN,
    "ENTERPRISE KEY ADMINS":  PrivilegeLevel.SERVER_ADMIN,
    
    "ACCOUNT OPERATORS":      PrivilegeLevel.DELEGATED_ADMIN,
    "PRINT OPERATORS":        PrivilegeLevel.DELEGATED_ADMIN,
    
    # ... etc
}


# Well-known SID suffixes (the part after the domain SID)
# These are GLOBAL Microsoft standards
WELL_KNOWN_RIDS: dict[str, PrivilegeLevel] = {
    "500":  PrivilegeLevel.DOMAIN_ADMIN,     # Built-in Administrator
    "502":  PrivilegeLevel.DOMAIN_ADMIN,     # KRBTGT
    "512":  PrivilegeLevel.DOMAIN_ADMIN,     # Domain Admins
    "516":  PrivilegeLevel.DOMAIN_ADMIN,     # Domain Controllers
    "518":  PrivilegeLevel.DOMAIN_ADMIN,     # Schema Admins
    "519":  PrivilegeLevel.DOMAIN_ADMIN,     # Enterprise Admins
    # ...
}

def classify(node: Node) -> PrivilegeLevel:
    """Return the privilege level of a node based on standard AD knowledge."""
    
    # Check well-known RID (last part of SID)
    rid = node.objectid.split("-")[-1]
    if rid in WELL_KNOWN_RIDS:
        return WELL_KNOWN_RIDS[rid]
    
    # Check well-known group name
    name = node.label.split("@")[0].upper()
    if name in WELL_KNOWN_GROUPS:
        return WELL_KNOWN_GROUPS[name]
    
    # Fallback: standard user
    return PrivilegeLevel.STANDARD_USER