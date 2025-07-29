from datetime import datetime
from datetime import timedelta
from datetime import timezone

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_credentials_report
from hyperscale.kite.helpers import get_account_ids_in_scope


class AvoidRootUsageCheck:
    def __init__(self):
        self.check_id = "avoid-root-usage"
        self.check_name = "Avoid Root Usage"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that the root account password has not been used "
            "recently in any account in scope. Root account usage should be avoided "
            "for day-to-day tasks."
        )

    def run(self) -> CheckResult:
        account_ids = get_account_ids_in_scope()
        accounts_with_root_usage = []
        for account_id in account_ids:
            report = get_credentials_report(account_id)
            if "root" not in report:
                continue
            root_account = report["root"]
            password_last_used = root_account.get("password_last_used")
            if password_last_used in ["N/A", "no_information"]:
                continue
            if password_last_used:
                if isinstance(password_last_used, str):
                    if password_last_used.endswith("Z"):
                        password_last_used = datetime.fromisoformat(
                            password_last_used.replace("Z", "+00:00")
                        )
                    else:
                        password_last_used = datetime.fromisoformat(password_last_used)
                        password_last_used = password_last_used.replace(
                            tzinfo=timezone.utc
                        )
                now = datetime.now(timezone.utc)
                if password_last_used > now - timedelta(days=90):
                    accounts_with_root_usage.append(
                        {
                            "account_id": account_id,
                            "password_last_used": password_last_used.isoformat(),
                        }
                    )
        if accounts_with_root_usage:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    f"Root account password has been used in the last 90 days in "
                    f"{len(accounts_with_root_usage)} account(s)."
                ),
                details={
                    "accounts_with_root_usage": accounts_with_root_usage,
                },
            )
        return CheckResult(
            status=CheckStatus.PASS,
            reason="Root account password has not been used in the last 90 days in any "
            "account.",
        )
