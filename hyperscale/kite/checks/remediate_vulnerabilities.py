from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class RemediateVulnerabilitiesCheck:
    def __init__(self):
        self.check_id = "remediate-vulnerabilities"
        self.check_name = "Remediate Vulnerabilities"

    @property
    def question(self) -> str:
        return (
            "Are there processes and procedures in place to prioritize and remediate "
            "identified vulnerabilities based on risk assessment criteria?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that there are processes and procedures in place "
            "to prioritize and remediate identified vulnerabilities based on risk "
            "assessment criteria."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are vulnerabilities triaged and prioritized based on risk?\n"
            "- Are there defined SLAs for remediation based on severity?\n"
            "- Are remediation actions tracked and reviewed?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
