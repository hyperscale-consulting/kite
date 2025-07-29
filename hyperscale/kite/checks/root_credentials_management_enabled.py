from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization_features


class RootCredentialsManagementEnabledCheck:
    def __init__(self):
        self.check_id = "root-credentials-management-enabled"
        self.check_name = "Root Credentials Management Enabled"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that the IAM organization feature for root "
            "credentials management is enabled."
        )

    def run(self) -> CheckResult:
        features = get_organization_features()

        if "RootCredentialsManagement" in features:
            return CheckResult(
                status=CheckStatus.PASS,
                reason=(
                    "Root credentials management is enabled at the "
                    "organizational level."
                ),
            )

        return CheckResult(
            status=CheckStatus.FAIL,
            reason=(
                "Root credentials management is not enabled at the "
                "organizational level. This feature helps prevent the use of "
                "root account credentials for day-to-day operations."
            ),
        )
