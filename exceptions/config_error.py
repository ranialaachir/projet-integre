# exceptions/config_error.py

from .auto_pwn_exception import AutoPwnException

class ConfigError(AutoPwnException):
    """
    Raised when AutoPwn is misconfigured before execution statrs.
    Missing credentials, invalid base_url, bad token format.
    """
    def __init__(self, field:str, reason:str):
        self.field = field
        self.reason = reason
        super.__init__(
            f"Configuration error on '{field}: {reason}'"
        )