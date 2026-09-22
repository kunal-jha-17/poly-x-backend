"""One error shape for the whole API: {"error": {"code", "message", "details"}}."""
from typing import Any, Dict, Optional


class ApiError(Exception):
    def __init__(self, code: str, message: str, http_status: int, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.details = details

    def body(self) -> Dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message, "details": self.details}}


def no_active_policy(http_status: int) -> ApiError:
    return ApiError("NO_ACTIVE_POLICY", "No policy is active yet. Compile and approve a policy first.", http_status)
