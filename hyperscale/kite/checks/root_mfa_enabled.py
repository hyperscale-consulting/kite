from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_account_summary
from hyperscale.kite.data import get_organization_features
from hyperscale.kite.helpers import get_account_ids_in_scope
from hyperscale.kite.helpers import get_root_virtual_mfa_device


class RootMfaEnabledCheck:
    def __init__(self):
        self.check_id = "root-mfa-enabled"
        self.check_name = "Root MFA Enabled"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that root user MFA is enabled in all accounts "
            "with hardware MFA devices."
        )

    def run(self) -> CheckResult:
        # Check if root credentials are managed at the organizational level
        features = get_organization_features()
        root_credentials_managed = "RootCredentialsManagement" in features

        # Get the management account ID from the config
        config = Config.get()
        management_account_id = config.management_account_id

        # Determine which accounts to check
        if root_credentials_managed and management_account_id:
            # Only check the management account
            account_ids = [management_account_id]
        else:
            # Check all accounts in scope
            account_ids = get_account_ids_in_scope()

        # Track accounts without MFA and accounts with virtual MFA
        accounts_without_mfa = []
        accounts_with_virtual_mfa = []

        # Check each account
        for account_id in account_ids:
            # Get the account summary
            summary = get_account_summary(account_id)
            if summary is None:
                accounts_without_mfa.append(account_id)
                continue

            # Check if MFA is enabled
            if summary["AccountMFAEnabled"] != 1:
                accounts_without_mfa.append(account_id)
                continue

            # If MFA is enabled, check if it's a virtual MFA device
            virtual_mfa = get_root_virtual_mfa_device(account_id)
            if virtual_mfa is not None:
                accounts_with_virtual_mfa.append(account_id)

        # Determine if the check passed
        passed = len(accounts_without_mfa) == 0 and len(accounts_with_virtual_mfa) == 0

        if passed:
            if root_credentials_managed:
                reason = (
                    "Root MFA is enabled with hardware MFA device in the "
                    "management account."
                )
            else:
                reason = (
                    "Root MFA is enabled with hardware MFA devices in all accounts."
                )
            return CheckResult(status=CheckStatus.PASS, reason=reason)

        # Build failure message
        message_parts = []
        if accounts_without_mfa:
            message_parts.append(
                f"Root MFA is not enabled in {len(accounts_without_mfa)} accounts."
            )
        if accounts_with_virtual_mfa:
            message_parts.append(
                f"Root MFA is enabled with virtual MFA devices in "
                f"{len(accounts_with_virtual_mfa)} accounts."
            )
        reason = " ".join(message_parts)

        return CheckResult(
            status=CheckStatus.FAIL,
            reason=reason,
            details={
                "accounts_without_mfa": accounts_without_mfa,
                "accounts_with_virtual_mfa": accounts_with_virtual_mfa,
            },
        )
