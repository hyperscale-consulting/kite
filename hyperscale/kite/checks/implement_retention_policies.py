from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class ImplementRetentionPoliciesCheck:
    def __init__(self):
        self.check_id = "implement-retention-policies"
        self.check_name = "Implement Retention Policies"

    @property
    def question(self) -> str:
        return (
            "Are automated data retention policies implemented that align with legal, "
            "regulatory and organizational requirements?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that automated data retention policies are "
            "implemented that align with legal, regulatory and organizational "
            "requirements."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Is data automatically deleted when it is no longer needed?\n"
            "- Are automated retention policies in place for all kinds of data, "
            "including back-ups and log data?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
