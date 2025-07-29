from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.helpers import get_prowler_output
from hyperscale.kite.helpers import ProwlerResult


class UseLogsForAlertingCheck:
    def __init__(self):
        self.check_id = "use-logs-for-alerting"
        self.check_name = "Log-Based Alerting"

    @property
    def question(self) -> str:
        return (
            "Do you use logs for alerting on potentially malicious or "
            "unauthorized behavior?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that logs are being used for alerting on "
            "potentially malicious or unauthorized behavior."
        )

    def run(self) -> CheckResult:
        # Get Prowler check results
        prowler_results = get_prowler_output()
        guardduty_passed = self._check_passed(prowler_results, "guardduty_is_enabled")
        securityhub_passed = self._check_passed(prowler_results, "securityhub_enabled")

        message = (
            "Please confirm if you have implemented alerting for:\n"
            "1. CloudTrail logs (e.g., unauthorized API calls, console "
            "logins, IAM changes)\n"
            "2. VPC Flow Logs (e.g., unusual traffic patterns, connections "
            "to known malicious IPs)\n"
            "3. CloudWatch Logs (e.g., application errors, security events)\n"
            "4. AWS Config (e.g., configuration changes, compliance violations)\n"
            "5. Route53 Resolver Query Logs (e.g., DNS exfiltration attempts)\n"
            "6. Application specific logs\n\n"
            "Additional Context:\n"
            f"- GuardDuty Status: {'Enabled' if guardduty_passed else 'Disabled'}\n"
            "- SecurityHub Status: "
            f"{'Enabled' if securityhub_passed else 'Disabled'}\n\n"
            "Note: GuardDuty and SecurityHub can provide additional alerting "
            "capabilities for security events."
        )

        return CheckResult(status=CheckStatus.MANUAL, context=message)

    def _check_passed(
        self, checks: dict[str, list[ProwlerResult]], check_id: str
    ) -> bool:
        config = Config.get()
        if check_id in checks:
            results = checks[check_id]
            for result in results:
                if result.status != "PASS" and result.region in config.active_regions:
                    return False
            return True
        raise ValueError(f"Check {check_id} not found")
