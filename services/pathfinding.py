# services/pathfinding.py

from utils.request import BHRequest
from exceptions.no_path_error import NoPathError
from entities.path import Path
from entities.node import Node
from entities.edge import Edge

def get_path(bh_request:BHRequest, source_node, goal_node) -> Path:
	"""
	This function returns a dict of :
	node_keys : list : ['admincount', 'blocksinheritance', 'description', 'displayname', 'distinguishedname', 'domain', 'domainsid', 'dontreqpreauth', 'enabled', 'functionallevel', 'haslaps', 'hasspn', 'highvalue', 'lastcollected', 'lastlogon', 'lastlogontimestamp', 'lastseen', 'name', 'objectid', 'operatingsystem', 'operatingsystemname', 'operatingsystemversion', 'ownersid', 'passwordnotreqd', 'pwdlastset', 'pwdneverexpires', 'samaccountname', 'sensitive', 'serviceprincipalnames', 'sidhistory', 'system_tags', 'trustedtoauth', 'unconstraineddelegation', 'vulnerablenetlogonsecuritydescriptorcollected', 'whencreated']
	edge_keys : list : ['inheritancehash', 'isacl', 'isinherited', 'isprimarygroup', 'lastseen']
	nodes : dict : '36': {'label': 'VAGRANT@SEVENKINGDOMS.LOCAL', 'kind': 'User', 'kinds': ['Base', 'User', 'Tag_Tier_Zero'], 'objectId': 'S-1-5-21-4100227132-2050190331-2295276406-1000', 'isTierZero': True, 'isOwnedObject': False, 'lastSeen': '2026-04-12T20:16:01.922Z', 'properties': {'admincount': True, 'description': 'Vagrant User', 'displayname': 'Vagrant', 'distinguishedname': 'CN=VAGRANT,CN=USERS,DC=SEVENKINGDOMS,DC=LOCAL', 'domain': 'SEVENKINGDOMS.LOCAL', 'domainsid': 'S-1-5-21-4100227132-2050190331-2295276406', 'dontreqpreauth': False, 'enabled': True, 'hasspn': False, 'lastcollected': '2026-04-12T20:15:59.535264186Z', 'lastlogon': 1775492730, 'lastlogontimestamp': 1775238051, 'lastseen': '2026-04-12T20:16:01.922Z', 'name': 'VAGRANT@SEVENKINGDOMS.LOCAL', 'objectid': 'S-1-5-21-4100227132-2050190331-2295276406-1000', 'ownersid': 'S-1-5-21-4100227132-2050190331-2295276406-512', 'passwordnotreqd': False, 'pwdlastset': 1620819535, 'pwdneverexpires': True, 'samaccountname': 'vagrant', 'sensitive': False, 'serviceprincipalnames': [], 'sidhistory': [], 'system_tags': 'admin_tier_0', 'trustedtoauth': False, 'unconstraineddelegation': False, 'whencreated': 1775237744}}
	nodes['36'].keys() : ['label', 'kind', 'kinds', 'objectId', 'isTierZero', 'isOwnedObject', 'lastSeen', 'properties']
	edges : list[dict] : {'source': '36', 'target': '96', 'label': 'MemberOf', 'kind': 'MemberOf', 'lastSeen': '2026-04-12T20:15:59.535264186Z', 'properties': {'isacl': False, 'isprimarygroup': False, 'lastseen': '2026-04-12T20:15:59.535264186Z'}}
	"""
	query = (
	    f"MATCH p = shortestPath((n:{source_node.kind.value}) -[*1..10]-> (m:{goal_node.kind.value})) "
	    f"WHERE n.objectid = '{source_node.objectid}' "
	    f"AND m.objectid = '{goal_node.objectid}' RETURN p"
	)
	data = bh_request.bh_post("/api/v2/graphs/cypher", {
		"query": query,
		"include_properties": True
	})

	if data is None:
		raise NoPathError(source_node, goal_node)

	return extract_path(source_node, goal_node, data["data"])

def extract_path(source_node:Node, goal_node:Node, data:dict) -> Path:
	nodes_data = data["nodes"]
	nodes = {}
	for k, node_data in nodes_data.items():
		nodes[k] = Node(node_data["objectId"],
				node_data["kind"],
				node_data["label"],
				node_data["properties"]
			       )
	# Choose later on what to choose in properties
	edges_data = data["edges"]
	edges = []
	for edge_data in edges_data:
		edges.append(Edge(nodes[edge_data["source"]],
				  nodes[edge_data["target"]],
				  edge_data["kind"]
				 )
			     )
	# print(source_node.properties.keys())
	return Path(source_node, goal_node, edges)

# shortest path User --> Group 'Domain Admins'
# data["data"]:dict --> ['node_keys', 'edge_keys', 'edges', 'nodes', 'literals']
# node_keys: list --> ['admincount', 'blocksinheritance', 'description', 'displayname', 'distinguishedname', 'domain', 'domainsid', 'dontreqpreauth', 'enabled', 'functionallevel', 'haslaps', 'hasspn', 'highvalue', 'lastcollected', 'lastlogon', 'lastlogontimestamp', 'lastseen', 'name', 'objectid', 'operatingsystem', 'operatingsystemname', 'operatingsystemversion', 'ownersid', 'passwordnotreqd', 'pwdlastset', 'pwdneverexpires', 'samaccountname', 'sensitive', 'serviceprincipalnames', 'sidhistory', 'system_tags', 'trustedtoauth', 'unconstraineddelegation', 'vulnerablenetlogonsecuritydescriptorcollected', 'whencreated']
# edge_keys: list --> ['inheritancehash', 'isacl', 'isinherited', 'isprimarygroup', 'lastseen']
# edges: list --> {'source': '25', 'target': '45', 'label': 'MemberOf', 'kind': 'MemberOf', 'lastSeen': '2026-04-12T20:15:59.535264186Z', 'properties': {'isacl': False, 'isprimarygroup': False, 'lastseen': '2026-04-12T20:15:59.535264186Z'}}
# nodes: dict --> ['105', '23', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '36', '39', '40', '41', '44', '45', '46', '69', '96']
# 25 {'label': 'MAESTER.PYCELLE@SEVENKINGDOMS.LOCAL', 'kind': 'User', 'kinds': ['Base', 'User'], 'objectId': 'S-1-5-21-4100227132-2050190331-2295276406-1121', 'isTierZero': False, 'isOwnedObject': False, 'lastSeen': '2026-04-12T20:16:01.889Z', 'properties': {'admincount': False, 'description': 'Maester Pycelle', 'distinguishedname': 'CN=MAESTER.PYCELLE,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL', 'domain': 'SEVENKINGDOMS.LOCAL', 'domainsid': 'S-1-5-21-4100227132-2050190331-2295276406', 'dontreqpreauth': False, 'enabled': True, 'hasspn': False, 'lastcollected': '2026-04-12T20:15:59.535264186Z', 'lastlogon': 0, 'lastlogontimestamp': -1, 'lastseen': '2026-04-12T20:16:01.889Z', 'name': 'MAESTER.PYCELLE@SEVENKINGDOMS.LOCAL', 'objectid': 'S-1-5-21-4100227132-2050190331-2295276406-1121', 'ownersid': 'S-1-5-21-4100227132-2050190331-2295276406-512', 'passwordnotreqd': False, 'pwdlastset': 1775238233, 'pwdneverexpires': True, 'samaccountname': 'maester.pycelle', 'sensitive': False, 'serviceprincipalnames': [], 'sidhistory': [], 'trustedtoauth': False, 'unconstraineddelegation': False, 'whencreated': 1775238233}}
# literals : []
