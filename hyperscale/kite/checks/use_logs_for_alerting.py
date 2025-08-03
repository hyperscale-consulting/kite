from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import find_failed_accounts_and_regions


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
        guardduty_failing = find_failed_accounts_and_regions("guardduty_is_enabled")
        securityhub_failing = find_failed_accounts_and_regions("securityhub_enabled")

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
            "Additional Context:\n\n"
            "- GuardDuty Status: "
        )
        if guardduty_failing:
            message += "*NOT* enabled across all accounts and regions"
        else:
            message += "enabled across all accounts and regions"
        message += "\n\n"
        message += "- SecurityHub Status: "
        if securityhub_failing:
            message += "*NOT* enabled across all accounts and regions"
        else:
            message += "enabled across all accounts and regions"

        message += (
            "\n\nNote: GuardDuty and SecurityHub can provide additional "
            "alerting capabilities for security events."
        )

        return CheckResult(status=CheckStatus.MANUAL, context=message)
