# main.py
import os
import sys
from dotenv import load_dotenv

from rich.console import Console

from entities.client import Client
from entities.node import Node
from entities.node_kind import NodeKind
from utils.request import BHRequest
from services.pathfinding import get_path
from exceptions.no_path_error import NoPathError
from exceptions.auto_pwn_exception import AutoPwnException
from entities.edge import Edge
from entities.edge_kind import EdgeKind
from entities.path import Path
from services.reporting import *
from services.parse_objects import parse_edge, parse_node, parse_path


load_dotenv()

# ─── 1. Load credentials ────────────────────────────────────────────────────

TOKEN_ID  = os.getenv("BLOODHOUND_TOKEN_ID")
TOKEN_KEY = os.getenv("BLOODHOUND_TOKEN_KEY")
BH_URL    = os.getenv("BLOODHOUND_URL", "http://127.0.0.1:8080")

client = Client(TOKEN_ID, TOKEN_KEY, BH_URL)
bh = BHRequest(client)
client.check_credentials()
print_check(f"Credentials loaded — connecting to {BH_URL}")

# ─── 2. Connectivity check ───────────────────────────────────────────────────

print_title("Step 1 — Checking API connectivity")
result = bh.bh_get("/api/v2/self")
if result is None:
    print_error("Could not reach BloodHound. Check BH_URL and that the server is running.")
    sys.exit(1)
print_check(f"Connected. Token belongs to: {result.get('data', {}).get('principal_name', '?')}")

# ─── 3. Raw Cypher query — list domains ──────────────────────────────────────
# Sanity check that the Neo4j data is populated and the Cypher endpoint works.

print_title("Step 2 — Querying domains in Neo4j")
domain_result = bh.bh_post("/api/v2/graphs/cypher", 
    {
        "query": "MATCH (d:Domain) RETURN d",
        "include_properties": True
    }
)
if domain_result is None:
	print_error("Cypher query failed. Is data collected and ingested?")
	sys.exit(1)

nodes = domain_result.get("data", {}).get("nodes", {})
print_check(f"Found {len(nodes)} domain(s):")
for node in nodes.values():
    print_node((parse_node(node)))

# ─── 4. Find a Kerberoastable user ───────────────────────────────────────────

print_title("\nStep 3 — Finding Kerberoastable users")
kerb_result = bh.bh_post("/api/v2/graphs/cypher", {
    "query": "MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true RETURN u",
    "include_properties": True
})
kerb_nodes = kerb_result.get("data", {}).get("nodes", {}) if kerb_result else {}
if not kerb_nodes:
	print_warning("No Kerberoastable users found (or query failed).")
else:
	print_check(f"Found {len(kerb_nodes)} Kerberoastable user(s):")
	for node in kerb_nodes.values():
		spns = node["properties"].get("serviceprincipalnames", [])
		print(f"    • {node['label']}  SPNs: {spns}") # TODO : format

# ─── 5. Find Domain Admins group objectId ────────────────────────────────────

print_title("\nStep 4 — Locating Domain Admins group")
da_result = bh.bh_post("/api/v2/graphs/cypher", {
    "query": "MATCH (g:Group) WHERE g.name STARTS WITH 'DOMAIN ADMINS' RETURN g",
    "include_properties": True
})
da_nodes = da_result.get("data", {}).get("nodes", {}) if da_result else {}
if not da_nodes:
	print_error("Domain Admins group not found.")
	sys.exit(1)

da_data    = list(da_nodes.values())[0]
da_node    = Node(da_data["objectId"], NodeKind.GROUP, da_data["label"], da_data["properties"])
print_node(da_node)

# ─── 6. Find a user to path from ─────────────────────────────────────────────

print_title("Step 5 — Finding a user to path from")
user_result = bh.bh_post("/api/v2/graphs/cypher", {
    "query": "MATCH (u:User) WHERE u.enabled = true RETURN u LIMIT 5",
    "include_properties": True
})
user_nodes = user_result.get("data", {}).get("nodes", {}) if user_result else {}
if not user_nodes:
    print_error("No enabled users found.")
    sys.exit(1)

print_check(f"Found {len(user_nodes)} enabled user(s):")
for u_data in user_nodes.values():
    print_node(parse_node(u_data))

# ─── 7. Shortest path to Domain Admins ───────────────────────────────────────

print_title("Step 6 — Shortest path to Domain Admins")
path_found = False
for u_data in user_nodes.values():
    source = parse_node(u_data)
    if source is None:
        continue
    print_check(f"Trying: {source.label} → {da_node.label}")
    try:
        path = get_path(bh, source, da_node)
        # Filter out None edges from unknown EdgeKinds before rendering
        path.edges = [e for e in path.edges if e is not None]
        if not path.edges:
            print_warning(f"Path found but all edges were unknown kinds, skipping.")
            continue
        print_check(f"Path found! Length: {path.length} hop(s)")
        console.print(format_path(path, index=1))
        path_found = True
        break
    except NoPathError:
        print_warning(f"No path from {source.label}, trying next...")
    except AutoPwnException as e:
        print_error(f"Tool error: {e}")
        break

if not path_found:
    print_warning("No path found from any of the sampled users.")

print_done("All checks complete.")