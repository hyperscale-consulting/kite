"""Check for absence of access keys for any user."""

from typing import Any

from kite.data import get_credentials_report
from kite.helpers import get_account_ids_in_scope

CHECK_ID = "no-access-keys"
CHECK_NAME = "No Access Keys"


def check_no_access_keys() -> dict[str, Any]:
    """
    Check if any users have access keys enabled.

    This check verifies that no users in any account in scope have access keys enabled.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - users_with_keys: List of dictionaries containing:
                    - account_id: str
                    - user_name: str
    """
    try:
        # Get all account IDs in scope
        account_ids = get_account_ids_in_scope()

        # Track users with access keys
        users_with_keys: list[dict[str, str]] = []

        # Check each account
        for account_id in account_ids:
            # Get the credentials report
            report = get_credentials_report(account_id)

            # Check each user in the report
            for user in report["users"]:
                # Check if access keys are enabled
                if (
                    user["access_key_1_active"] == "true"
                    or user["access_key_2_active"] == "true"
                ):
                    users_with_keys.append(
                        {"account_id": account_id, "user_name": user["user"]}
                    )

        # Determine if the check passed
        passed = len(users_with_keys) == 0

        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS" if passed else "FAIL",
            "details": {
                "message": (
                    "No access keys found for any users in any accounts."
                    if passed
                    else (
                        f"Access keys found for {len(users_with_keys)} users "
                        f"across {len(set(u['account_id'] for u in users_with_keys))} "
                        "accounts."
                    )
                ),
                "users_with_keys": users_with_keys,
            },
        }

    except Exception as e:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {
                "message": f"Error checking for access keys: {str(e)}",
            },
        }


# Attach the check ID and name to the function
check_no_access_keys._CHECK_ID = CHECK_ID
check_no_access_keys._CHECK_NAME = CHECK_NAME
