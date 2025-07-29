from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class RootAccountMonitoringCheck:
    def __init__(self):
        self.check_id = "root-account-monitoring"
        self.check_name = "Root Account Monitoring"

    @property
    def question(self) -> str:
        return (
            "Are there systems and procedures in place to monitor for and respond to "
            "root account misuse?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that there are systems and procedures in place to "
            "monitor for and respond to root account misuse."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Are there systems in place to monitor root account activity?\n"
            "- Are there procedures to respond to suspicious root account activity?\n"
            "- Are these procedures regularly tested and updated?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
