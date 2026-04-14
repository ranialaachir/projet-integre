# services/pathfinding.py

from utils.request import BHRequest
from exceptions.no_path_error import NoPathError
from entities.path import Path
from entities.node import Node
from .parse_objects import parse_path

def get_path(bh_request:BHRequest, source_node:Node, goal_node:Node) -> Path:
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

	return parse_path(source_node, goal_node, data["data"])