# repositories/bloodhound_repository.py

from repositories.base_repository import BaseRepository
from exceptions.api_error import ApiError

class BloodHoundRepository(BaseRepository):
    def __init__(self):
        super().__init__()  # client + bh ready

    def connectivity_check(self) -> dict:
        result = self.bh_request.bh_get("/api/v2/self")
        if result is None:
            raise ApiError(0, "/api/v2/self", "Could not reach BloodHound.")
        return result