"""Check for root user security."""

from typing import Dict, Any
from datetime import datetime, timedelta, timezone

from kite.helpers import get_account_ids_in_scope
from kite.data import get_credentials_report


CHECK_ID = "avoid-root-usage"
CHECK_NAME = "Avoid Root Usage"


def check_root_user_usage() -> Dict[str, Any]:
    """
    Check if the root account is being used for day-to-day tasks.

    This check verifies that the root account password has not been used recently
    in any account in scope.

    Returns:
        Dict containing the check result.
    """
    try:
        # Get all account IDs in scope
        account_ids = get_account_ids_in_scope()

        # Track accounts with root user usage
        accounts_with_root_usage = []

        # Check each account
        for account_id in account_ids:
            try:
                # Get the credentials report for this account
                report = get_credentials_report(account_id)

                # Check if the root account exists in the report
                if "root" not in report:
                    continue

                # Get the root account details
                root_account = report["root"]

                # Check if the root account password has been used recently
                password_last_used = root_account.get("password_last_used")

                # Handle the case where password_last_used is "N/A" or "no_information"
                if password_last_used in ["N/A", "no_information"]:
                    continue

                if password_last_used:
                    try:
                        # Convert to datetime if it's a string
                        if isinstance(password_last_used, str):
                            # Handle different date formats
                            if password_last_used.endswith("Z"):
                                # UTC timezone
                                password_last_used = datetime.fromisoformat(
                                    password_last_used.replace("Z", "+00:00")
                                )
                            else:
                                # Try to parse without timezone info
                                password_last_used = datetime.fromisoformat(
                                    password_last_used
                                )
                                # Make it timezone-aware (UTC)
                                password_last_used = password_last_used.replace(
                                    tzinfo=timezone.utc
                                )

                        # Get current time in UTC
                        now = datetime.now(timezone.utc)

                        # Check if the password was used in the last 90 days
                        if password_last_used > now - timedelta(days=90):
                            accounts_with_root_usage.append(
                                {
                                    "account_id": account_id,
                                    "password_last_used": password_last_used.isoformat(),
                                }
                            )
                    except ValueError as e:
                        # Log the error but continue checking other accounts
                        print(f"Error parsing date for account {account_id}: {str(e)}")
            except Exception as e:
                # Log the error but continue checking other accounts
                print(f"Error checking account {account_id}: {str(e)}")

        # Determine the overall status
        if accounts_with_root_usage:
            return {
                "check_id": CHECK_ID,
                "check_name": CHECK_NAME,
                "status": "FAIL",
                "details": {
                    "message": (
                        f"Root account password has been used in the last 90 days in "
                        f"{len(accounts_with_root_usage)} account(s). "
                        "This is a security risk."
                    ),
                    "accounts_with_root_usage": accounts_with_root_usage,
                },
            }

        # If we get here, no root accounts have been used recently
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "Root account password has not been used in the last 90 days "
                    "in any account."
                )
            },
        }

    except Exception as e:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {"message": f"Error checking root user usage: {str(e)}"},
        }


# Attach the check ID and name to the function
check_root_user_usage._CHECK_ID = CHECK_ID
check_root_user_usage._CHECK_NAME = CHECK_NAME
