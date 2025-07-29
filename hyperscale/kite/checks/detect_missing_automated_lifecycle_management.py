from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.utils import print_config_compliance_for_rules


class DetectMissingAutomatedLifecycleManagementCheck:
    def __init__(self):
        self.check_id = "detect-missing-automated-lifecycle-management"
        self.check_name = "Detect Missing Automated Lifecycle Management"

    @property
    def question(self) -> str:
        return (
            "Are there config rules in place that detect and alert when automated "
            "lifecycle management is not turned on when it should be?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that config rules are in place to detect and alert "
            "when automated lifecycle management is not turned on when it should be."
        )

    def run(self) -> CheckResult:
        message = "AWS Config Rules for automated lifecycle management:\n\n"
        message += print_config_compliance_for_rules(["s3-lifecycle-policy-check"])
        message += (
            "Please review the above and consider:\n"
            "- Are Config rules configured to detect missing lifecycle policies in "
            "each account and region?\n"
            "- Are alerts configured for non-compliant resources?\n"
            "- Is auto-remediation configured where appropriate?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
