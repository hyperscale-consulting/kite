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
            "intelligence used?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that AWS managed services that automatically update "
            "with the latest threat intelligence are used."
        )

    def run(self) -> CheckResult:
        message = (
            "Some AWS managed services, such as GuardDuty, WAF, Inspector, and Shield "
            "Advanced, automatically incorporate new threat intelligence as "
            "threats emerge over time. Adopting these services can help reduce the "
            "overall effort of staying up-to-date with emerging threats."
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
