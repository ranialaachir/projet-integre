# main.py
import os
import sys
from dotenv import load_dotenv

from entities.client import Client
from entities.node import Node
from entities.node_kind import NodeKind
from utils.request import BHRequest
from services.pathfinding import get_path
from exceptions.no_path_error import NoPathError
from exceptions.auto_pwn_exception import AutoPwnException

load_dotenv()

# ─── 1. Load credentials ────────────────────────────────────────────────────

TOKEN_ID  = os.getenv("BLOODHOUND_TOKEN_ID")
TOKEN_KEY = os.getenv("BLOODHOUND_TOKEN_KEY")
BH_URL    = os.getenv("BLOODHOUND_URL", "http://127.0.0.2:8080")

client = Client(TOKEN_ID, TOKEN_KEY, BH_URL)
bh = BHRequest(client)
client.check_credentials()
print(f"[+] Credentials loaded — connecting to {BH_URL}")

# ─── 2. Connectivity check ───────────────────────────────────────────────────
# GET /api/v2/self is an authenticated endpoint that returns your token info.
# If this works, auth signing is correct.

print("\n[*] Step 1 — Checking API connectivity...")
result = bh.bh_get("/api/v2/self")
if result is None:
    print("[-] Could not reach BloodHound. Check BH_URL and that the server is running.")
    sys.exit(1)
print(f"[+] Connected. Token belongs to: {result.get('data', {}).get('principal_name', '?')}")


# ─── 3. Raw Cypher query — list domains ──────────────────────────────────────
# Sanity check that the Neo4j data is populated and the Cypher endpoint works.

print("\n[*] Step 2 — Querying domains in Neo4j...")
domain_result = bh.bh_post("/api/v2/graphs/cypher", {
    "query": "MATCH (d:Domain) RETURN d",
    "include_properties": True
})
if domain_result is None:
	print("[-] Cypher query failed. Is data collected and ingested?")
	sys.exit(1)

nodes = domain_result.get("data", {}).get("nodes", {})
print(f"[+] Found {len(nodes)} domain(s):")
for node in nodes.values():
	print(f"    • {node['label']}  (objectId: {node['objectId']})")

# ─── 4. Find a Kerberoastable user ───────────────────────────────────────────

print("\n[*] Step 3 — Finding Kerberoastable users...")
kerb_result = bh.bh_post("/api/v2/graphs/cypher", {
    "query": "MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true RETURN u",
    "include_properties": True
})
kerb_nodes = kerb_result.get("data", {}).get("nodes", {}) if kerb_result else {}
if not kerb_nodes:
	print("[-] No Kerberoastable users found (or query failed).")
else:
	print(f"[+] Found {len(kerb_nodes)} Kerberoastable user(s):")
	for node in kerb_nodes.values():
		spns = node["properties"].get("serviceprincipalnames", [])
		print(f"    • {node['label']}  SPNs: {spns}")

# ─── 5. Find Domain Admins group objectId ────────────────────────────────────

print("\n[*] Step 4 — Locating Domain Admins group...")
da_result = bh.bh_post("/api/v2/graphs/cypher", {
    "query": "MATCH (g:Group) WHERE g.name STARTS WITH 'DOMAIN ADMINS' RETURN g",
    "include_properties": True
})
da_nodes = da_result.get("data", {}).get("nodes", {}) if da_result else {}
if not da_nodes:
	print("[-] Domain Admins group not found.")
	sys.exit(1)

da_data    = list(da_nodes.values())[0]
da_node    = Node(da_data["objectId"], NodeKind.GROUP, da_data["label"], da_data["properties"])
print(f"[+] Domain Admins: {da_node.label}  ({da_node.objectid})")

# ─── 6. Shortest path from first enabled user to Domain Admins ───────────────

print("\n[*] Step 5 — Finding a user to path from...")
user_result = bh.bh_post("/api/v2/graphs/cypher", {
    "query": "MATCH (u:User) WHERE u.enabled = true RETURN u LIMIT 5",
    "include_properties": True
})
user_nodes = user_result.get("data", {}).get("nodes", {}) if user_result else {}
if not user_nodes:
	print("[-] No enabled users found.")
	sys.exit(1)

for u_data in user_nodes.values():
	source = Node(u_data["objectId"], NodeKind.USER, u_data["label"], u_data["properties"])
	print(f"\n[*] Step 6 — Shortest path: {source.label} → Domain Admins")
	try:
		path = get_path(bh, source, da_node)
		print(f"[+] Path found! Length: {path.length} hop(s)")
		for i, edge in enumerate(path.edges):
			print(f"    {i+1}. {edge.source_node.label}  --[{edge.kind}]-->  {edge.goal_node.label}")
		break  # stop at first successful path
	except NoPathError as e:
		print(f"    (no path from this user, trying next...)")
	except AutoPwnException as e:
		print(f"[-] Tool error: {e}")
		break
else:
	print("[-] No path found from any of the sampled users.")

print("\n[✓] All checks complete.")
