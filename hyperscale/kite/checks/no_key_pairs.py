from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.helpers import get_account_ids_in_scope
from hyperscale.kite.helpers import get_account_key_pairs


class NoKeyPairsCheck:
    def __init__(self):
        self.check_id = "no-key-pairs"
        self.check_name = "No EC2 Key Pairs"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that no EC2 key pairs exist in any account in scope. "
            "Using SSM Instance Connect is recommended instead of key pairs."
        )

    def run(self) -> CheckResult:
        account_ids = get_account_ids_in_scope()
        accounts_with_key_pairs = []
        for account_id in account_ids:
            key_pairs = get_account_key_pairs(account_id)
            if key_pairs:
                accounts_with_key_pairs.append(
                    {
                        "account_id": account_id,
                        "key_pairs": [kp["KeyName"] for kp in key_pairs],
                    }
                )
        passed = len(accounts_with_key_pairs) == 0
        return CheckResult(
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            reason=(
                "No EC2 key pairs found in any accounts."
                if passed
                else (
                    f"EC2 key pairs found in {len(accounts_with_key_pairs)} accounts."
                )
            ),
            details={
                "accounts_with_key_pairs": accounts_with_key_pairs,
            },
        )
