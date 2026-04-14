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
from entities.edge import Edge
from entities.edge_kind import EdgeKind
from entities.path import Path
from services.reporting import print_report, format_edge, format_node

load_dotenv()


# ── Convertir les nodes bruts en objets Node ──────────────────────────────────
def parse_node(n: dict) -> Node:
    """Convertit un nœud brut de l'API BloodHound en entité Node."""
    kind_str = n.get("kind", "Unknown")
    try:
        kind = NodeKind(kind_str)
    except ValueError:
        kind = NodeKind.USER  # fallback si type inconnu
    return Node(
        objectid   = n.get("objectId", ""),
        kind       = kind,
        label      = n.get("label", kind_str),
        properties = n.get("properties", {}),
    )



# ── Convertir les edges bruts en objets Edge ──────────────────────────────────
def parse_edge(e: dict) -> Edge | None:
    """Convertit un edge brut de l'API BloodHound en entité Edge."""
    try:
        kind = EdgeKind(e.get("kind", ""))
    except ValueError:
        print(f"  [!] Edge type inconnu ignoré : {e.get('kind')}")
        return None

    source = node_map.get(e.get("source"))
    target = node_map.get(e.get("target"))

    if source is None or target is None:
        return None

    return Edge(source_node=source, goal_node=target, kind=kind)

# ── Reconstruire les paths à partir des edges ─────────────────────────────────
# BloodHound retourne un graphe aplati (nodes + edges) sans structure de paths.
# On regroupe les edges consécutifs en paths en suivant les chaînes source→target.
def build_paths(edges: list[Edge]) -> list[Path]:
    """
    Reconstruit des Path depuis une liste d'edges aplatis.
    Stratégie : on cherche les nœuds qui ne sont jamais une target (= sources racines),
    puis on suit la chaîne depuis chaque racine.
    """
    all_targets  = {e.goal_node.objectid  for e in edges}
    all_sources  = {e.source_node.objectid for e in edges}
    root_ids     = all_sources - all_targets  # nœuds sans parent = débuts de paths

    # Index : source_objectid → liste d'edges partant de ce nœud
    edge_index: dict[str, list[Edge]] = {}
    for e in edges:
        edge_index.setdefault(e.source_node.objectid, []).append(e)

    paths: list[Path] = []

    def walk(current_id: str, chain: list[Edge]):
        nexts = edge_index.get(current_id, [])
        if not nexts:
            # On est arrivé à un nœud terminal → path complet
            if chain:
                paths.append(Path(
                    source_node = chain[0].source_node,
                    goal_node   = chain[-1].goal_node,
                    edges       = list(chain),
                ))
            return
        for edge in nexts:
            chain.append(edge)
            walk(edge.goal_node.objectid, chain)
            chain.pop()

    for root_id in root_ids:
        walk(root_id, [])

    return paths


# ─── 1. Load credentials ────────────────────────────────────────────────────

TOKEN_ID  = os.getenv("BLOODHOUND_TOKEN_ID")
TOKEN_KEY = os.getenv("BLOODHOUND_TOKEN_KEY")
BH_URL    = os.getenv("BLOODHOUND_URL", "http://127.0.0.2:8080")

client = Client(TOKEN_ID, TOKEN_KEY, BH_URL)
bh = BHRequest(client)
client.check_credentials()
print(f"[+] Credentials loaded — connecting to {BH_URL}")

# ─── 2. Connectivity check ───────────────────────────────────────────────────

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
	# print(f"    • {node['label']}  (objectId: {node['objectId']})")
    n = parse_node(node)
    print(format_node(n))

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
# ─── 7. Reporting — real paths from BloodHound ───────────────────────────────
print("\n[*] Step 7 — Fetching real attack paths from BloodHound...\n")

# ── Requête : tous les chemins courts vers Domain Admins (max 10 hops)
raw = bh.bh_post("/api/v2/graphs/cypher", {
    "query": """
        MATCH p = shortestPath((u:User)-[*1..10]->(g:Group))
        WHERE g.name STARTS WITH 'DOMAIN ADMINS'
        AND u.enabled = true
        RETURN p
    """,
    "include_properties": True
})

if raw is None:
    print("[-] Query failed.")
    sys.exit(1)

data       = raw.get("data", {})
raw_nodes  = data.get("nodes", {})   # dict  { objectId -> node_dict }
raw_edges  = data.get("edges", [])   # list  [ edge_dict ]

print(f"[+] Raw response: {len(raw_nodes)} node(s), {len(raw_edges)} edge(s)")

node_map: dict[str, Node] = {
    oid: parse_node(n)
    for oid, n in raw_nodes.items()
}


parsed_edges = [parse_edge(e) for e in raw_edges]
parsed_edges = [e for e in parsed_edges if e is not None]  # filtrer les None



real_paths = build_paths(parsed_edges)
print(f"[+] {len(real_paths)} path(s) reconstructed\n")

if not real_paths:
    print("[-] Aucun path reconstruit. Vérifie que les données sont bien ingérées.")
else:
    print_report(paths=real_paths, domain="sevenkingdoms.local")