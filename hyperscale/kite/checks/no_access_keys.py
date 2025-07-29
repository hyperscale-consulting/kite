from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_credentials_report
from hyperscale.kite.helpers import get_account_ids_in_scope


class NoAccessKeysCheck:
    def __init__(self):
        self.check_id = "no-access-keys"
        self.check_name = "No Access Keys"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that no users in any account in scope have access "
            "keys enabled."
        )

    def run(self) -> CheckResult:
        account_ids = get_account_ids_in_scope()
        users_with_keys = []
        for account_id in account_ids:
            report = get_credentials_report(account_id)
            for user in report["users"]:
                if (
                    user["access_key_1_active"] == "true"
                    or user["access_key_2_active"] == "true"
                ):
                    users_with_keys.append(
                        {"account_id": account_id, "user_name": user["user"]}
                    )
        passed = len(users_with_keys) == 0
        return CheckResult(
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            reason=(
                "No access keys found for any users in any accounts."
                if passed
                else (
                    f"Access keys found for {len(users_with_keys)} users "
                    f"across {len(set(u['account_id'] for u in users_with_keys))} "
                    "accounts."
                )
            ),
            details={
                "users_with_keys": users_with_keys,
            },
        )
