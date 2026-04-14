# entities/client.py

from dataclasses import dataclass, field

@dataclass
class Client:
    _token_id: str
    _token_key: str
    base_url: str

    # Hide sensitive fields from being printed
    _sensitive_fields: list[str] = field(default_factory=lambda: ["_token_key"], repr=False)

    def check_credentials(self) -> bool:
        missing = [
            name for name, val in {
                "token_id":  self._token_id,
                "token_key": self._token_key,
                "base_url":  self.base_url,
            }.items() if not val
        ]
        if missing:
            raise ValueError(f"Missing BloodHound credentials: {missing}")
        return True

    def __post_init__(self):
        """Called automatically after __init__"""
        self.check_credentials()   # Validate on creation
