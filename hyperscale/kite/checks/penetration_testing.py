from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class PenetrationTestingCheck:
    def __init__(self):
        self.check_id = "perform-regular-pen-testing"
        self.check_name = "Perform Regular Penetration Testing"

    @property
    def question(self) -> str:
        return "Is regular penetration testing performed to validate security controls?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that regular penetration testing is performed to "
            "validate security controls."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Is penetration testing performed on a regular schedule?\n"
            "- Are findings from penetration tests tracked and remediated?\n"
            "- Are findings from penetration tests analysed to identify systemic "
            "issues to inform automated tests and developer training?\n"
            "- Are penetration test results reviewed and shared with relevant "
            "stakeholders?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
