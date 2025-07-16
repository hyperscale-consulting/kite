from enum import Enum
from typing import Protocol


def make_finding(
    check_id: str,
    check_name: str,
    status: str,
    reason: str,
    description: str,
    details: dict | None = None,
) -> dict:
    if details is None:
        details = dict(message=reason)
    return {
        "check_id": check_id,
        "check_name": check_name,
        "status": status,
        "description": description,
        "reason": reason,
        "details": details or {},
    }


class CheckStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL = "MANUAL"


class CheckResult:
    def __init__(
        self, status: CheckStatus, reason: str | None = None, context: str | None = None
    ):
        self.status = status
        self.reason = reason
        self.context = context


class Check(Protocol):
    def run(self) -> CheckResult: ...

    @property
    def question(self) -> str: ...

    @property
    def description(self) -> str: ...
