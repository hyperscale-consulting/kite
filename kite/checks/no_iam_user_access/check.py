"""Check for use of IAM users for console access."""

from typing import Any

from kite.data import get_credentials_report
from kite.helpers import get_account_ids_in_scope
from kite.helpers import manual_check

CHECK_ID = "no-iam-user-access"
CHECK_NAME = "No IAM User Access"


def check_no_iam_user_access() -> dict[str, Any]:
    """
    Check if IAM users are used for console access, rather than federation.

    This check:
    1. Gets credentials reports for all in-scope accounts
    2. Identifies users with console access
    3. If no users with console access exist, automatically passes
    4. If users with console access exist, prompts the user to confirm if these
       represent systematic use of IAM users or exceptional scenarios

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - users_with_console_access: List of users with console access (if any)
    """
    try:
        # Get in-scope accounts
        account_ids = get_account_ids_in_scope()

        # Get credentials reports for each account
        users_with_console_access = []
        for account_id in account_ids:
            try:
                report = get_credentials_report(account_id)
                # Check both root and user accounts
                for user in report["users"]:
                    if user.get("password_enabled", "false").lower() == "true":
                        users_with_console_access.append(
                            {
                                "account_id": account_id,
                                "user_name": user["user"],
                            }
                        )
            except Exception as e:
                return {
                    "check_id": CHECK_ID,
                    "check_name": CHECK_NAME,
                    "status": "ERROR",
                    "details": {
                        "message": f"Error getting credentials report for account {account_id}: {str(e)}",
                    },
                }

        # If no users with console access found, automatically pass
        if not users_with_console_access:
            return {
                "check_id": CHECK_ID,
                "check_name": CHECK_NAME,
                "status": "PASS",
                "details": {
                    "message": "No IAM users with console access found in in-scope accounts.",
                },
            }

        # Create message for manual check
        message = (
            "IAM users with console access were found in your in-scope accounts. "
            "Consider the following factors:\n"
            "- Are these instances of systematic use of IAM users for console access?\n"
            "- Or do they represent exceptional scenarios (e.g. emergency access)?\n\n"
            "Users with Console Access:\n"
        )

        # Add user details to message
        for user in users_with_console_access:
            message += f"- User {user['user_name']} in account {user['account_id']}\n"

        # Use manual_check to get the user's response
        result = manual_check(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            message=message,
            prompt=(
                "Do the instances of IAM user console access represent systematic "
                "use of IAM users rather than federation?"
            ),
            pass_message=(
                "IAM user console access is only used for exceptional scenarios, "
                "not as a systematic approach."
            ),
            fail_message=(
                "IAM user console access should be replaced with federation where "
                "possible."
            ),
            default=False,
        )

        # Add the users to the result details
        if "details" in result:
            result["details"]["users_with_console_access"] = users_with_console_access

        return result

    except Exception as e:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {
                "message": f"Error checking for IAM user console access: {str(e)}",
            },
        }


check_no_iam_user_access._CHECK_ID = CHECK_ID
check_no_iam_user_access._CHECK_NAME = CHECK_NAME
