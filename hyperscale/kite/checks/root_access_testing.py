from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class RootAccessTestingCheck:
    def __init__(self):
        self.check_id = "root-access-testing"
        self.check_name = "Root Access Testing"

    @property
    def question(self) -> str:
        return (
            "Is root user access periodically tested to ensure it is functioning in "
            "emergency situations?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that root user access is periodically tested to "
            "ensure it is functioning in emergency situations. Testing should include "
            "both password and MFA device verification."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Is root user access tested on a regular schedule?\n"
            "- Does the testing include both password and MFA device verification?\n"
            "- Is the testing process documented and include emergency procedures?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
