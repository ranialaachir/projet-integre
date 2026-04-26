# BloodHound Automation Tool

Automated Active Directory attack path analysis using the BloodHound CE API.

---

## What is this?

Manual BloodHound analysis is tedious — clicking through the UI, running queries one by one, piecing together attack paths by hand. This tool automates that process by querying BloodHound CE programmatically to enumerate attack paths, identify high-value targets, and produce structured findings without touching the UI.

Target environment: **GOAD-Mini** (`sevenkingdoms.local`) — an intentionally vulnerable Active Directory lab for practicing offensive techniques.

---

## What it does

- Enumerate all users, groups, and computers in the domain
- Find shortest attack paths from any principal to Domain Admins
- Map BloodHound edges to concrete exploitation techniques (Kerberoasting, ACL abuse, Pass-the-Hash, DCSync, GenericWrite, etc.)
- Rank findings by path length and exploitability
- Output structured, readable reports

## What it does NOT do

- It is not a collector — use `bloodhound-python` or `SharpHound` for data collection
- It is not a replacement for the BloodHound UI

---

## Requirements

- Python 3.10+
- Libraries : rich, requests
- BloodHound CE v8.7+ (Kali package or Docker)
- Neo4j running and populated with AD data
- A BloodHound API token (token ID + token key)
- GOAD-Mini lab running and collected

```bash
pip install -r requirements.txt
```

---

## Setup

**1. Clone the repo**
```bash
git clone https://github.com/ranialaachir/projet-integre.git
cd projet-integre
```

**2. Create your `.env` file** (never committed)
```bash
cp .env.example .env
# Fill in your values
```

**3. Collect AD data** (if not already done)
```bash
bloodhound-python \
  -d sevenkingdoms.local \
  -u 'vagrant' -p 'vagrant' \
  -dc kingslanding.sevenkingdoms.local \
  -ns 192.168.56.10 \
  -c All --zip
```
Then upload the zip via the BloodHound CE UI → File Ingest.

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```env
BLOODHOUND_TOKEN_ID=your_token_id_here
BLOODHOUND_TOKEN_KEY=your_token_key_here
BLOODHOUND_URL=http://<SERVER_IP>:8083

DC_IP=<AD_DN_IP>
AD_DOMAIN=sevenkingdoms.local
```

To generate a token: BloodHound UI → top right menu → **API Tokens** → Create Token.

---
## Project Naming Conventions
```
<type>/<short-description>

feature/write-dacl-strategy
feature/kerberos-techniques
fix/shadow-creds-cleanup
refactor/bloodyad-base
docs/readme-update
````
---

## Project Structure

```
bloodhound-auto/
├── entities/
│   ├── __init__.py
│   ├── client.py          # BHClient — stores credentials and base URL
│   ├── edge.py            # Edge dataclass — relationship between two nodes
│   ├── node.py            # Node dataclass — AD principal (user, group, computer)
│   ├── path.py            # Path dataclass — ordered sequence of nodes and edges
│   └── exploit_result.py  # Structured output from any exploit strategy
├── exceptions/
│   ├── __init__.py
│   ├── auto_pwn_exception.py  # Base exception for the tool
│   ├── hop_failed_error.py    # Raised when a single hop in a path cannot be exploited
│   └── no_path_error.py       # Raised when no attack path exists to a target
├── services/
│   ├── __init__.py
│   ├── enumeration.py     # Find users, groups, computers in the domain
│   ├── pathfinding.py     # Shortest paths and attack path analysis
│   ├── scoring.py         # Scoring / prioritization (scorer chaque finding par criticité)
│   ├── parse_objects.py   # Extract nodes, edges and paths from JSON data
│   └── reporting.py       # Output formatting and structured findings
├── strategies/
│   ├── __init__.py
│   ├── exploit_strategy.py    # Abstract base class for all exploit strategies
│   ├── dc_sync.py             # DCSync rights exploitation
│   ├── generic_write.py       # GenericWrite ACL abuse
│   ├── kerberoast.py          # Kerberoastable service account targeting
│   ├── add_member.py          # Add member to a Group
│   └── pass_the_hash.py       # Pass-the-Hash lateral movement
├── utils/
│   ├── __init__.py
│   ├── auth.py            # BHAuth — HMAC request signing logic
│   └── request.py         # BHRequest — get, post, delete HTTP methods
│   ├── cred_store.py      # Temporary
│   ├── platform.py        # Check the environment
│   └── request.py         # Runs the cmd tools
├── main.py                # Orchestrate
├── .env                   # Your secrets (never committed)
├── .env.example           # Template for others
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Architecture Overview

The codebase is organized around four layers:

- **`entities/`** — core data models (`Node`, `Edge`, `Path`) and the API client wrapper
- **`services/`** — high-level logic: enumeration, pathfinding, and reporting
- **`strategies/`** — pluggable exploit strategies, each mapping a BloodHound edge type to a concrete attack technique
- **`utils/`** — low-level HTTP and authentication helpers (HMAC signing, raw requests)

Exceptions are centralized under `exceptions/` to allow services and strategies to signal failure conditions cleanly without returning sentinel values.

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

## Target Lab: GOAD-Mini

| Property | Value |
|---|---|
| Domain | `sevenkingdoms.local` |
| Domain Controller | `kingslanding.sevenkingdoms.local` |
| DC IP | `192.168.56.10` |
| Collection user | `vagrant` / `vagrant` (local account) |

> `vagrant` is a local machine account — it will not appear as a domain user in BloodHound. Domain users are AD principals like `JOFFREY.BARATHEON@SEVENKINGDOMS.LOCAL`.

---

## References

- [BloodHound CE Docs](https://support.bloodhoundenterprise.io/)
- [GOAD - Game of Active Directory](https://github.com/Orange-Cyberdefense/GOAD)
- [BloodHound API Spec](http://localhost:8080/api/v2/spec) (local, requires running instance)
