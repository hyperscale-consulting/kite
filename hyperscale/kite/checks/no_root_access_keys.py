from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_account_summary
from hyperscale.kite.helpers import get_account_ids_in_scope


class NoRootAccessKeysCheck:
    def __init__(self):
        self.check_id = "no-root-access-keys"
        self.check_name = "No Root Access Keys"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return "This check verifies that no accounts in scope have root access keys."

    def run(self) -> CheckResult:
        account_ids = get_account_ids_in_scope()
        accounts_with_root_keys = []
        for account_id in account_ids:
            summary = get_account_summary(account_id)
            if summary and summary["AccountAccessKeysPresent"] > 0:
                accounts_with_root_keys.append(account_id)
        passed = len(accounts_with_root_keys) == 0
        return CheckResult(
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            reason=(
                "No root access keys found in any accounts."
                if passed
                else (
                    f"Root access keys found in "
                    f"{len(accounts_with_root_keys)} accounts."
                )
            ),
            details={
                "accounts_with_root_keys": accounts_with_root_keys,
            },
        )
