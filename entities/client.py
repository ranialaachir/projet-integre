# entities/client.py

from dataclasses import dataclass, field
from typing import Any
from exceptions.config_error import ConfigError

@dataclass
class Client:
    _token_id: str
    _token_key: str
    base_url: str
    ldap_connection: Any = field(default=None, repr=False)
    # Hide sensitive fields from being printed
    _sensitive_fields: list[str] = field(default_factory=lambda: ["_token_key"], repr=False)

    def check_credentials(self) -> bool:
        for name, val in {
            "token_id":  self._token_id,
            "token_key": self._token_key,
            "base_url":  self.base_url,
        }.items():
            if not val:
                raise ConfigError(field=name, reason="must not be empty")
        return True

    def __post_init__(self):
        """Called automatically after __init__"""
        self.check_credentials()   # Validate on creation
