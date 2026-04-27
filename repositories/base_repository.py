# repositories/base_repository.py

from utils.request import BHRequest
from entities.client import Client
from exceptions.config_error import ConfigError
import os

CREDS = {
    "dc_ip":    os.getenv("DC_IP",       "192.168.56.10"),
    "domain":   os.getenv("AD_DOMAIN",   "sevenkingdoms.local"),
    "username": os.getenv("AD_USERNAME", "vagrant"),
    "password": os.getenv("AD_PASSWORD", "vagrant"),
}

class BaseRepository:
    def __init__(self):
        TOKEN_ID  = os.getenv("BLOODHOUND_TOKEN_ID")
        TOKEN_KEY = os.getenv("BLOODHOUND_TOKEN_KEY")
        BH_URL    = os.getenv("BLOODHOUND_URL", "http://127.0.0.1:8080")

        try:
            self.client = Client(TOKEN_ID, TOKEN_KEY, BH_URL)
            self.bh_request = BHRequest(self.client)
        except ConfigError:
            raise
        except Exception as e:
            raise RuntimeError(f"Unexpected error while initializing client: {e}") from e