from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_cloudfront_origin_access_identities
from hyperscale.kite.helpers import get_account_ids_in_scope


class MigrateFromOaiCheck:
    def __init__(self):
        self.check_id = "migrate-from-oai"
        self.check_name = "Migrate from CloudFront Origin Access Identities"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that no accounts are using legacy CloudFront Origin "
            "Access Identities (OAIs) and have migrated to the newer Origin Access "
            "Control (OAC) mechanism."
        )

    def run(self) -> CheckResult:
        in_scope_accounts = get_account_ids_in_scope()
        failing_resources = []
        for account_id in in_scope_accounts:
            account_oais = get_cloudfront_origin_access_identities(account_id)
            if account_oais:
                failing_resources.append(
                    {
                        "account_id": account_id,
                        "resource_details": {"oais": account_oais},
                    }
                )
        passed = len(failing_resources) == 0
        return CheckResult(
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            reason=(
                "No accounts are using legacy CloudFront Origin Access Identities."
                if passed
                else (
                    f"Found {len(failing_resources)} accounts still using legacy "
                    "CloudFront Origin Access Identities."
                )
            ),
            details={
                "failing_resources": failing_resources,
            },
        )
