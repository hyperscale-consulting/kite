from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class DfdsCheck:
    def __init__(self):
        self.check_id = "dfds"
        self.check_name = "Data Flow Diagrams"

    @property
    def question(self) -> str:
        return (
            "Are there up-to-date DFDs capturing all major trust boundaries, data "
            "flows and components?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that there are up-to-date DFDs capturing all major "
            "trust boundaries, data flows and components."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are DFDs up-to-date?\n"
            "- Do DFDs capture all major trust boundaries?\n"
            "- Do DFDs capture all data flows and components?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
