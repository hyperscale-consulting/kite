from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class MonitorSecretsCheck:
    def __init__(self):
        self.check_id = "monitor-secrets"
        self.check_name = "Monitor Secrets"

    @property
    def question(self) -> str:
        return (
            "Are secrets monitored for unusual activity and are automated remediation "
            "actions triggered where appropriate?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that secrets are monitored for unusual activity and "
            "that automated remediation actions are triggered where appropriate."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are secrets monitored for unusual access patterns, such as attempts to "
            "delete secrets, or attempts to read secrets from unexpected principals or "
            "networks?\n"
            "- Are automated remediation actions triggered for suspicious activity?\n"
            "- Are alerts sent to appropriate teams for investigation?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
