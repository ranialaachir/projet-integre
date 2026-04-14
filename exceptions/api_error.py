# exceptions/api_error.py
from .auto_pwn_exception import AutoPwnException

class ApiError(AutoPwnException):
    """
    Raised when the BloodHound API returns an unexpected response.
    Wraps HTTP-level failures so the rest of the tool stays API-agnostic.
    """
    def __init__(self, status_code: int, endpoint: str, detail: str = ""):
        self.status_code = status_code
        self.endpoint    = endpoint
        super().__init__(
            f"BloodHound API error {status_code} on '{endpoint}'"
            + (f": {detail}" if detail else "")
        )