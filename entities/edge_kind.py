# entities/edge_kind.py

from enum import Enum

class EdgeKind(Enum):
	MEMBER_OF = "MemberOf"
	HAS_SESSION = "HasSession"
	ADMIN_TO = "AdminTo"
	GENERIC_WRITE = "GenericWrite"
	GENERIC_ALL = "GenericAll"
	WRITE_DACL = "WriteDacl"
	WRITE_OWNER = "WriteOwner"
	DCSYNC = "DCSync"
	GET_CHANGES = "GetChanges"
	GET_CHANGES_ALL = "GetChangesAll"
	KERBEROASTABLE = "HasSPNConfigured"
	ALLOWED_TO_DELEGATE = "AllowedToDelegate"
	OWNS = "Owns"