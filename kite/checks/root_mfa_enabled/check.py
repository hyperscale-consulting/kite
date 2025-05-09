"""Check for root user MFA enabled."""

from typing import Dict, Any

from kite.config import Config
from kite.helpers import (
    get_account_ids_in_scope,
    get_root_virtual_mfa_device,
)
from kite.data import get_account_summary, get_organization_features


CHECK_ID = "root-mfa-enabled"
CHECK_NAME = "Root MFA Enabled"


def check_root_mfa_enabled() -> Dict[str, Any]:
    """
    Check if root user MFA is enabled in all accounts.

    This check verifies that:
    1. Root user MFA is enabled in all accounts (AccountMFAEnabled = 1)
    2. If MFA is enabled, it should be a hardware MFA device, not a virtual one

    If root credentials are managed at the organizational level, the check is only
    performed on the management account. Otherwise, it is performed on all accounts.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - accounts_without_mfa: List of accounts that don't have MFA enabled
                - accounts_with_virtual_mfa: List of accounts that have virtual MFA
    """
    try:
        # Check if root credentials are managed at the organizational level
        features = get_organization_features()
        root_credentials_managed = "RootCredentialsManagement" in features

        # Get the management account ID from the config
        config = Config.get()
        management_account_id = config.management_account_id

        # Determine which accounts to check
        if root_credentials_managed:
            if not management_account_id:
                return {
                    "check_id": CHECK_ID,
                    "check_name": CHECK_NAME,
                    "status": "ERROR",
                    "details": {
                        "message": (
                            "Root credentials management is enabled, but management "
                            "account ID could not be determined."
                        )
                    },
                }

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

        # Build the message
        if passed:
            if root_credentials_managed:
                message = (
                    "Root MFA is enabled with hardware MFA device in the "
                    "management account."
                )
            else:
                message = (
                    "Root MFA is enabled with hardware MFA devices in all accounts."
                )
        else:
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
            message = " ".join(message_parts)

        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS" if passed else "FAIL",
            "details": {
                "message": message,
                "accounts_without_mfa": accounts_without_mfa,
                "accounts_with_virtual_mfa": accounts_with_virtual_mfa,
            },
        }

    except Exception as e:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {
                "message": f"Error checking for root MFA: {str(e)}",
            },
        }


# Attach the check ID and name to the function
check_root_mfa_enabled._CHECK_ID = CHECK_ID
check_root_mfa_enabled._CHECK_NAME = CHECK_NAME
