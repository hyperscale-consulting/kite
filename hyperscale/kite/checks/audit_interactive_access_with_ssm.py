from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class AuditInteractiveAccessWithSSMCheck:
    def __init__(self):
        self.check_id = "audit-interactive-access-with-ssm"
        self.check_name = "Audit Interactive Access with SSM"

    @property
    def question(self) -> str:
        return (
            "Is interactive access, where required, provided via SSM Session Manager "
            "with session activity logged in CloudWatch or S3 to provide an audit "
            "trail?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that interactive access, where required, is provided "
            "via SSM Session Manager and that session activity is logged to provide "
            "an audit trail."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Is SSM Session Manager used for interactive access instead of "
            "direct SSH/RDP connections?\n"
            "- Is session activity logged to CloudWatch Logs or S3?\n"
            "- Are session logs retained for an appropriate period?\n"
            "- Is there monitoring and alerting for unusual session activity?\n"
            "- Are session logs reviewed regularly for security incidents?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
