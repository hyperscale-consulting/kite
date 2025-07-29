from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization


class AwsOrganizationsUsageCheck:
    def __init__(self):
        self.check_id = "aws-organizations-usage"
        self.check_name = "AWS Organizations Usage"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies whether AWS Organizations is being used for account "
            "management."
        )

    def run(self) -> CheckResult:
        org = get_organization()
        if org is None:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="AWS Organizations is not being used for account management.",
            )
        else:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="AWS Organizations is being used for account management.",
                details={
                    "master_account_id": org.master_account_id,
                    "arn": org.arn,
                    "feature_set": org.feature_set,
                },
            )
