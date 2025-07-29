from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class AccountStandardsCheck:
    def __init__(self):
        self.check_id = "account-standards"
        self.check_name = "Account Standards"

    @property
    def question(self) -> str:
        return "Are new accounts vended with suitable standards already defined?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that new accounts are vended with suitable standards "
            "already defined."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are new accounts vended with suitable standards?\n"
            "- Are the standards defined before account creation?\n"
            "- Are the standards consistently applied across all new accounts?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
