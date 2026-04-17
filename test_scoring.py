import os
from dotenv import load_dotenv

from entities.client import Client
from entities.node import Node
from entities.node_kind import NodeKind
from utils.request import BHRequest
from services.scoring import prioritize

load_dotenv()

# Init
client = Client(
    os.getenv("BLOODHOUND_TOKEN_ID"),
    os.getenv("BLOODHOUND_TOKEN_KEY"),
    os.getenv("BLOODHOUND_URL", "http://127.0.0.1:8080")
)
client.check_credentials()
bh = BHRequest(client)

# Nodes mock — simule enumeration.py
nodes = [
    Node("S-1-5-21-USER-JOFFREY", NodeKind.USER,
         "JOFFREY.BARATHEON@SEVENKINGDOMS.LOCAL",
         {"hasspn": True, "enabled": True}),

    Node("S-1-5-21-USER-CERSEI", NodeKind.USER,
         "CERSEI.LANNISTER@SEVENKINGDOMS.LOCAL",
         {"enabled": False}),

    Node("S-1-5-21-USER-VAGRANT", NodeKind.USER,
         "VAGRANT@SEVENKINGDOMS.LOCAL",
         {"dontreqpreauth": True, "enabled": True}),

    Node("S-1-5-21-USER-TYWIN", NodeKind.USER,
         "TYWIN.LANNISTER@SEVENKINGDOMS.LOCAL",
         {"admincount": 1, "enabled": True}),

    Node("S-1-5-21-COMPUTER-DC01", NodeKind.COMPUTER,
         "KINGSLANDING.SEVENKINGDOMS.LOCAL",
         {"enabled": True}),

    Node("S-1-5-21-GROUP-DA", NodeKind.GROUP,
         "DOMAIN ADMINS@SEVENKINGDOMS.LOCAL",
         {"highvalue": True}),

    Node("S-1-5-21-DOMAIN", NodeKind.DOMAIN,
         "SEVENKINGDOMS.LOCAL", {}),

    Node("S-1-5-21-GPO", NodeKind.GPO,
         "DEFAULT DOMAIN POLICY@SEVENKINGDOMS.LOCAL", {}),
]

# Scoring
result = prioritize(nodes, bh)

# Affichage
print("\n=== TOP SOURCES ===")
for i, n in enumerate(result["source_nodes"], 1):
    print(f"  {i}. [{n.kind.value}] {n.label}")

print("\n=== TOP TARGETS ===")
for i, n in enumerate(result["target_nodes"], 1):
    print(f"  {i}. [{n.kind.value}] {n.label}")

nb_s = len(result["source_nodes"])
nb_t = len(result["target_nodes"])
print(f"\n→ {nb_s} sources x {nb_t} targets = {nb_s * nb_t} requêtes Cypher max")