from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class AutomateDeploymentsCheck:
    def __init__(self):
        self.check_id = "automate-deployments"
        self.check_name = "Automated Deployments"

    @property
    def question(self) -> str:
        return (
            "Are deployments fully automated, removing all need for persistent human "
            "access to production environments?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that deployments are fully automated, removing all "
            "need for persistent human access to production environments."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are all deployments fully automated through CI/CD pipelines?\n"
            "- Is there no persistent human access required to production environments?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
