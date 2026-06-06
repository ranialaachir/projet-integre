# entities/edge_kind.py

from enum import Enum

class EdgeKind(Enum):
	MEMBER_OF           = "MemberOf"     # state edge
	HAS_SESSION         = "HasSession"   # No
	ADMIN_TO            = "AdminTo"      # No
	GENERIC_WRITE       = "GenericWrite" # 11
	GENERIC_ALL         = "GenericAll"   # 12 GenericWrite + other stuff
	"""
	On User --> force change password (shadow creds or kerberoast)
	On Group --> add member
	On Computer --> RBCD
	On Domain --> grant DCSync rights via WriteDACL
	"""
	WRITE_DACL          = "WriteDacl"    # 21 Grant GenericAll or on domain objects fo GetChanges + GetChangesAll for DCSync
	WRITE_OWNER         = "WriteOwner"   # 22 WriteOwnerStrategy → bloodyAD set owner → then WriteDaclStrategy
	ADD_MEMBER          = "AddMember"    # AddMemberStrategy → bloodyAD add groupMember <group> <victim>
	DCSYNC              = "DCSync"
	GET_CHANGES         = "GetChanges"
	GET_CHANGES_ALL     = "GetChangesAll"
	KERBEROASTABLE      = "HasSPNConfigured"
	ALLOWED_TO_DELEGATE = "AllowedToDelegate"
	OWNS                = "Owns"
	COERCE_TO_TGT       = "CoerceToTGT"     # CoerceToTGTStrategy → responder/ntlmrelayx listener + coercion tool
	CONTAINS            = "Contains"        # not exploitable
	CAN_RDP_TO          = "CanRDPTo"        #
	CAN_PS_REMOTE_TO    = "CanPSRemoteTo"
	ALLOWED_TO_ACT      = "AllowedToAct"     # RBCD
	TRUSTED_BY          = "TrustedBy"
	FORCE_CHANGE_PW     = "ForceChangePassword"
	READ_LAPS_PASS      = "ReadLAPSPassword"
	# WriteOwnerRaw, AllExtendedRights, AddKeyCredentialLink,OwnsRaw, AddSelf, GPLink

"""
Some strategies are terminal (they directly give you credentials or 
access): AddMember, GenericWriteStrategy on a user, CoerceToTGT.
Some are enabling (they upgrade your rights so another strategy can run): 
WriteOwner → WriteDACL → GenericAll. 
You'd model this as chaining — WriteOwnerStrategy.exploit() 
returns an ExploitResult that effectively says 
"now you have WriteDACL on this object" and the engine queues 
the next strategy.
"""

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