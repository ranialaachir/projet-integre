# entities/edge_kind.py

from enum import Enum

class EdgeKind(Enum):
	MEMBER_OF           = "MemberOf"
	HAS_SESSION         = "HasSession"
	ADMIN_TO            = "AdminTo"
	GENERIC_WRITE       = "GenericWrite" # 11
	GENERIC_ALL         = "GenericAll"   # 12
	WRITE_DACL          = "WriteDacl"    # 21
	WRITE_OWNER         = "WriteOwner"   # 22
	ADD_MEMBER          = "AddMember"
	DCSYNC              = "DCSync"
	GET_CHANGES         = "GetChanges"
	GET_CHANGES_ALL     = "GetChangesAll"
	KERBEROASTABLE      = "HasSPNConfigured"
	ALLOWED_TO_DELEGATE = "AllowedToDelegate"
	OWNS                = "Owns"
	COERCE_TO_TGT       = "CoerceToTGT"
	CONTAINS            = "Contains"
	CAN_RDP_TO          = "CanRDPTo"        #
	CAN_PS_REMOTE_TO    = "CanPSRemoteTo"
	ALLOWED_TO_ACT      = "AllowedToAct"     # RBCD
	TRUSTED_BY          = "TrustedBy"
	FORCE_CHANGE_PW     = "ForceChangePassword"
	READ_LAPS_PASS      = "ReadLAPSPassword"

"""
https://www.reddit.com/r/Pentesting/comments/1rfkaum/bloodhound_edges_common_vs_rare_encounters_as_a/
https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/paths/graph-schema.edge-kinds.yaml 
CanRDPTo and CanPSRemoteTo
Owns edges on service account objects (whoever created the service account often still owns it) 
TrustedBy edges (external/forest trusts) 
AllowedToAct (RBCD) - finding this on DC objects is a gift
GetChangesAll directly on non-admin accounts
**On DCOnly:** Worth using when you're dealing with a large environment and want to scope your initial analysis. It reduces noise significantly but you'll miss workstation-based attack paths (HasSession, AdminTo chains). I usually run without DCOnly first for a full picture, then use it for reporting focus.

The most "surprising" pattern I've seen repeatedly: nested group memberships that nobody has audited in years, creating unexpected AdminTo paths on sensitive servers.
"""