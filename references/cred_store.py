# references/cred_store.py
# v2 : User will give what is controlled/owned and their secret and it will be added to a file
# or maybe it will be updated automatically

from __future__ import annotations

import threading
from typing import Optional

_lock = threading.Lock()

KNOWN_SECRETS = {
    "lord.varys"        : ":52ff2a79823d81d6a3f4f8261d7acc59",
    "administrator"     : ":c66d72021a2d4744409969a581a1705e",
    "krbtgt"            : ":50687f0656d56c91897cf952306a00b8",
    "tywin.lannister"   : ":af52e9ec3471788111a6308abff2e9b7",
    "cersei.lannister"  : "il0vejaime",
    "robert.baratheon"  : "iamthekingoftheworld",
    "petyr.baelish"     : "@littlefinger@",
    "joffrey.baratheon" : "1killerlion",
    "vagrant"           : "vagrant"
}

def enrich_creds(creds: dict) -> dict:
    """Inject known hash/password for the attacker if we have it."""
    username = creds.get("username", "").lower().split("@")[0]
    creds["secret"] = KNOWN_SECRETS[username]
    return creds

def normalize_username(raw: str) -> str:
    """
    'TYWIN.LANNISTER@SEVENKINGDOMS.LOCAL' → 'tywin.lannister'
    'sevenkingdoms.local\\vagrant'         → 'vagrant'
    'vagrant'                              → 'vagrant'
    """
    name = raw.strip().lower()
    if "@" in name:
        name = name.split("@")[0]
    if "\\" in name:
        name = name.split("\\")[-1]
    # Strip trailing $ for machine accounts? Keep it — it matters
    return name


def has_creds(username: str) -> bool:
    return normalize_username(username) in KNOWN_SECRETS


def get_secret(username: str) -> Optional[str]:
    return KNOWN_SECRETS.get(normalize_username(username))


def add_secret(username: str, secret: str) -> None:
    """Thread-safe credential insertion (called after successful exploit)."""
    key = normalize_username(username)
    with _lock:
        KNOWN_SECRETS[key] = secret


def get_all_known_users() -> list[str]:
    """Return all usernames we have creds for."""
    return list(KNOWN_SECRETS.keys())


def is_hash(secret: str) -> bool:
    """Check if secret is an NT hash (starts with ':')"""
    return secret.startswith(":")

"""
def enrich_creds(creds: dict) -> dict:
    Inject known hash/password for the attacker.
    username = normalize_username(creds.get("username", ""))
    secret = get_secret(username)
    if secret is None:
        raise KeyError(f"No credentials known for '{username}'")

    creds = dict(creds)  # don't mutate original
    creds["username"] = username

    if is_hash(secret):
        creds["password"] = secret       # bloodyAD accepts :hash as password
        creds["nt_hash"] = secret[1:]    # pure hash without ':'
    else:
        creds["password"] = secret
        creds["nt_hash"] = ""

    return creds
"""