from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class SnsDataProtectionPoliciesCheck:
    def __init__(self):
        self.check_id = "sns-data-protection-policies"
        self.check_name = "SNS Data Protection Policies"

    @property
    def question(self) -> str:
        return (
            "Are SNS data protection policies used to automatically identify, "
            "mask and alert on unexpected sensitive data in SNS messages?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that SNS data protection policies are used "
            "to automatically identify and mask unexpected sensitive data in "
            "SNS messages."
        )

    def run(self) -> CheckResult:
        # TODO: Add permissions so we can do some automated support with this check.
        message = (
            "Consider the following factors:\n"
            "- Are data protection policies configured for SNS topics?\n"
            "- Are alarms in place to alert on unexpected sensitive data?\n"
            "- Is sensitive data denied, masked or redacted as appropriate?\n"
            "- Do the policies align with your data classification scheme and "
            "inventory?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
