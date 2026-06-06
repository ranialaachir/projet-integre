# references/cred_store.py
# references/cred_store.py addition
import json, os

STATE_FILE = "tmp/owned_state.json"

def save_credential(username: str, secret: str) -> None:
    os.makedirs("tmp", exist_ok=True)
    try:
        state = json.load(open(STATE_FILE)) if os.path.exists(STATE_FILE) else {}
    except json.JSONDecodeError:
        state = {}
    state[username.lower()] = secret
    json.dump(state, open(STATE_FILE, "w"), indent=2)

# # v2 : User will give what is controlled/owned and their secret and it will be added to a file
# # or maybe it will be updated automatically

# KNOWN_SECRETS = {
#     "lord.varys"        : ":52ff2a79823d81d6a3f4f8261d7acc59",
#     "administrator"     : ":c66d72021a2d4744409969a581a1705e",
#     "krbtgt"            : ":50687f0656d56c91897cf952306a00b8",
#     "tywin.lannister"   : ":af52e9ec3471788111a6308abff2e9b7",
#     "cersei.lannister"  : "il0vejaime",
#     "robert.baratheon"  : "iamthekingoftheworld",
#     "petyr.baelish"     : "@littlefinger@",
#     "joffrey.baratheon" : "1killerlion",
#     "vagrant"           : "vagrant"
# }

def enrich_creds(creds: dict) -> dict:
    """Inject known hash/password for the attacker if we have it."""
    username = creds.get("username", "").lower().split("@")[0]
    creds["secret"] = KNOWN_SECRETS[username]
    return creds