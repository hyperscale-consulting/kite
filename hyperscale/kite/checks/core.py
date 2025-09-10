from enum import Enum
from typing import Protocol


class CheckStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL = "MANUAL"


class CheckResult:
    def __init__(
        self,
        status: CheckStatus,
        reason: str = "",
        context: str = "",
        details: dict | None = None,
    ):
        self.status = status
        self.reason = reason
        self.context = context
        self.details = details


class Check(Protocol):
    def run(self) -> CheckResult: ...

    @property
    def question(self) -> str: ...

    @property
    def description(self) -> str: ...

    @property
    def check_id(self) -> str: ...

    @property
    def check_name(self) -> str: ...

    @property
    def criticality(self) -> int: ...

    @property
    def difficulty(self) -> int: ...
