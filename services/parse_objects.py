# services/parse_objects.py

from entities.node import Node
from entities.node_kind import NodeKind
from entities.edge import Edge
from entities.edge_kind import EdgeKind
from entities.path import Path

# from : /api/v2/graphs/cypher
def parse_node(n: dict) -> Node | None:
    """Convert Node JSON to Node Object"""
    try:
        kind = NodeKind(n.get("kind", ""))
    except ValueError:
        print(f"  [!] Node Kind is Unknown : {n.get('kind')}")
        return None
    return Node(
        objectid   = n.get("objectId", ""),
        kind       = kind,
        label      = n.get("label", "Unknown"),
        properties = n.get("properties", {}), # TODO: Choose later on what to choose in properties
    )

def parse_edge(e: dict) -> Edge | None:
    """Convertit un edge brut de l'API BloodHound en entité Edge."""
    try:
        kind = EdgeKind(e.get("kind", ""))
    except ValueError:
        print(f"  [!] Edge Kind is Unknown : {e.get('kind')}")
        return None

    source = e.get("source")
    target = e.get("target")

    if source is None or target is None:
        print(f"  [!] Target or Source Node are Empty")
        return None

    return Edge(source_node=source, goal_node=target, kind=kind)

def parse_path(source_node: Node, goal_node: Node, data: dict) -> Path:
    nodes_data = data["nodes"]
    nodes: dict[str, Node] = {}
    for k, node_data in nodes_data.items():
        parsed = parse_node(node_data)
        if parsed is not None:
            nodes[k] = parsed

    edges_data = data["edges"]
    edges: list[Edge] = []
    for edge_data in edges_data:
        try:
            kind = EdgeKind(edge_data.get("kind", ""))
        except ValueError:
            print(f"  [!] Edge Kind is Unknown : {edge_data.get('kind')}")
            continue  # skip unknown edges instead of appending None

        src = nodes.get(edge_data["source"])
        tgt = nodes.get(edge_data["target"])

        if src is None or tgt is None:
            print(f"  [!] Could not resolve nodes for edge {edge_data.get('kind')}")
            continue

        edges.append(Edge(source_node=src, goal_node=tgt, kind=kind))

    return Path(source_node, goal_node, edges)

def parse_path_1(source_node:Node, goal_node:Node, data:dict) -> Path:
	nodes_data = data.get("nodes", {})
	nodes = {}
	for k, node_data in nodes_data.items():
		nodes[k] = parse_node(node_data)
	
	edges_data = data.get("edges", {})
	edges = []
	for edge_data in edges_data:
		edges.append(parse_edge(edge_data))
	return Path(source_node, goal_node, edges)

# shortest path User --> Group 'Domain Admins'
# data["data"]:dict --> ['node_keys', 'edge_keys', 'edges', 'nodes', 'literals']
# node_keys: list --> ['admincount', 'blocksinheritance', 'description', 'displayname', 'distinguishedname', 'domain', 'domainsid', 'dontreqpreauth', 'enabled', 'functionallevel', 'haslaps', 'hasspn', 'highvalue', 'lastcollected', 'lastlogon', 'lastlogontimestamp', 'lastseen', 'name', 'objectid', 'operatingsystem', 'operatingsystemname', 'operatingsystemversion', 'ownersid', 'passwordnotreqd', 'pwdlastset', 'pwdneverexpires', 'samaccountname', 'sensitive', 'serviceprincipalnames', 'sidhistory', 'system_tags', 'trustedtoauth', 'unconstraineddelegation', 'vulnerablenetlogonsecuritydescriptorcollected', 'whencreated']
# edge_keys: list --> ['inheritancehash', 'isacl', 'isinherited', 'isprimarygroup', 'lastseen']
# edges: list --> {'source': '25', 'target': '45', 'label': 'MemberOf', 'kind': 'MemberOf', 'lastSeen': '2026-04-12T20:15:59.535264186Z', 'properties': {'isacl': False, 'isprimarygroup': False, 'lastseen': '2026-04-12T20:15:59.535264186Z'}}
# nodes: dict --> ['105', '23', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '36', '39', '40', '41', '44', '45', '46', '69', '96']
# 25 {'label': 'MAESTER.PYCELLE@SEVENKINGDOMS.LOCAL', 'kind': 'User', 'kinds': ['Base', 'User'], 'objectId': 'S-1-5-21-4100227132-2050190331-2295276406-1121', 'isTierZero': False, 'isOwnedObject': False, 'lastSeen': '2026-04-12T20:16:01.889Z', 'properties': {'admincount': False, 'description': 'Maester Pycelle', 'distinguishedname': 'CN=MAESTER.PYCELLE,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL', 'domain': 'SEVENKINGDOMS.LOCAL', 'domainsid': 'S-1-5-21-4100227132-2050190331-2295276406', 'dontreqpreauth': False, 'enabled': True, 'hasspn': False, 'lastcollected': '2026-04-12T20:15:59.535264186Z', 'lastlogon': 0, 'lastlogontimestamp': -1, 'lastseen': '2026-04-12T20:16:01.889Z', 'name': 'MAESTER.PYCELLE@SEVENKINGDOMS.LOCAL', 'objectid': 'S-1-5-21-4100227132-2050190331-2295276406-1121', 'ownersid': 'S-1-5-21-4100227132-2050190331-2295276406-512', 'passwordnotreqd': False, 'pwdlastset': 1775238233, 'pwdneverexpires': True, 'samaccountname': 'maester.pycelle', 'sensitive': False, 'serviceprincipalnames': [], 'sidhistory': [], 'trustedtoauth': False, 'unconstraineddelegation': False, 'whencreated': 1775238233}}
# literals : []