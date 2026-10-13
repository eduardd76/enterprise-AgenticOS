"""Failure contracts (AOS-0001 §11.11): typed failure classes, each declaring retry safety."""

from __future__ import annotations


class SyscallError(Exception):
    # code -> is it safe for the caller to retry the same request unchanged?
    RETRY_SAFE = {
        "INVALID_REQUEST": False,
        "UNKNOWN_CAPABILITY": False,
        "UNAUTHORIZED": False,
        "POLICY_DENIED": False,
        "APPROVAL_REQUIRED": False,
        "APPROVAL_DENIED": False,
        "BUDGET_EXHAUSTED": False,
        "NO_FEASIBLE_PROVIDER": True,
        "PROVIDER_ERROR": True,
        "DEADLINE_EXCEEDED": True,
        "STALE_STATE": False,
        "PARTIAL_SIDE_EFFECT": False,
        "DEADLOCK": True,
        "REVOKED": False,
        "CONFIDENCE_INSUFFICIENT": False,
        "NOT_FOUND": False,
    }

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message

    @property
    def retry_safe(self) -> bool:
        return self.RETRY_SAFE.get(self.code, False)

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "retry_safe": self.retry_safe}
