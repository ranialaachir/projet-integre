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
- Map BloodHound edges to concrete exploitation techniques (Kerberoasting, ACL abuse, etc.)
- Rank findings by path length and exploitability
- Output structured, readable reports

## What it does NOT do

- It is not a collector — use `bloodhound-python` or `SharpHound` for data collection
- It is not a replacement for the BloodHound UI
- It is not an active exploitation tool — analysis and path finding only

---

## Requirements

- Python 3.10+
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
git clone https://github.com/yourname/bloodhound-auto.git
cd bloodhound-auto
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
  -c All --zip --dns-tcp -w 1
```
Then upload the zip via the BloodHound CE UI → File Ingest.

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```env
BLOODHOUND_TOKEN_ID=your_token_id_here
BLOODHOUND_TOKEN_KEY=your_token_key_here
BLOODHOUND_URL=http://localhost:8080
```

To generate a token: BloodHound UI → top right menu → **API Tokens** → Create Token.

---

## Project Structure

```
bloodhound-auto/
├── core/
│   ├── entities/
│   │   ├── __init__.py
│   │   └── bh_client.py      # BHClient — stores credentials and URL
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── bh_auth.py         # BHAuth — HMAC signing logic
│   │   └── bh_request.py      # BHRequest — get, post, delete methods
│   └── models/
│       ├── __init__.py
│       └── graph.py           # Node, Edge, Path dataclasses
├── modules/
│   ├── enumeration.py         # Find users, groups, computers
│   ├── pathfinding.py         # Shortest paths, attack path analysis
│   └── reporting.py           # Output and formatting
├── main.py
├── .env                       # Your secrets (never committed)
├── .env.example               # Template for others
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Key Technical Notes

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
