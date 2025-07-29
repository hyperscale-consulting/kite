from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class CwDataProtectionPoliciesCheck:
    def __init__(self):
        self.check_id = "cw-data-protection-policies"
        self.check_name = "CloudWatch Data Protection Policies"

    @property
    def question(self) -> str:
        return (
            "Are CloudWatch data protection policies used to automatically identify, "
            "mask and alert on unexpected sensitive data in CloudWatch log files?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that CloudWatch data protection policies are used "
            "to automatically identify and mask unexpected sensitive data in "
            "CloudWatch log files."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are data protection policies configured for CloudWatch log groups?\n"
            "- Are alarms in place to alert on unexpected sensitive data?\n"
            "- Do the policies align with your data classification scheme and "
            "inventory?\n"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
