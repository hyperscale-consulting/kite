from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class AwsManagedServicesThreatIntelCheck:
    def __init__(self):
        self.check_id = "aws-managed-services-threat-intel"
        self.check_name = "AWS Managed Services Threat Intelligence"

    @property
    def question(self) -> str:
        return (
            "Are AWS managed services that automatically update with the latest threat "
            "intelligence used effectively?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that AWS managed services that automatically update "
            "with the latest threat intelligence are used effectively."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are AWS managed services with built-in threat intelligence being used "
            "where appropriate? (e.g GuardDuty, WAF, Inspector, Shield Advanced)"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
