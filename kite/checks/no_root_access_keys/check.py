"""Check for absence of root access keys."""

from typing import Dict, Any

from kite.helpers import get_account_ids_in_scope
from kite.data import get_account_summary


CHECK_ID = "no-root-access-keys"
CHECK_NAME = "No Root Access Keys"


def check_no_root_access_keys() -> Dict[str, Any]:
    """
    Check if any accounts have root access keys.

    This check verifies that no accounts in scope have root access keys.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - accounts_with_root_keys: List of accounts that have root access keys
    """
    try:
        # Get all account IDs in scope
        account_ids = get_account_ids_in_scope()

        # Track accounts with root access keys
        accounts_with_root_keys = []

        # Check each account
        for account_id in account_ids:
            # Get the account summary
            summary = get_account_summary(account_id)

            # Check if root access keys are present
            if summary["AccountAccessKeysPresent"] > 0:
                accounts_with_root_keys.append(account_id)

        # Determine if the check passed
        passed = len(accounts_with_root_keys) == 0

        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS" if passed else "FAIL",
            "details": {
                "message": (
                    "No root access keys found in any accounts."
                    if passed
                    else (
                        f"Root access keys found in "
                        f"{len(accounts_with_root_keys)} accounts."
                    )
                ),
                "accounts_with_root_keys": accounts_with_root_keys,
            },
        }

    except Exception as e:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {
                "message": f"Error checking for root access keys: {str(e)}",
            },
        }


# Attach the check ID and name to the function
check_no_root_access_keys._CHECK_ID = CHECK_ID
check_no_root_access_keys._CHECK_NAME = CHECK_NAME
