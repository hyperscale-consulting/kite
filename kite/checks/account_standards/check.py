"""Check for new accounts vended with suitable standards already defined."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "account-standards"
CHECK_NAME = "Account Standards"


def check_account_standards() -> dict[str, Any]:
    """
    Check if new accounts are vended with suitable standards already defined.


    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    # Define the message and prompts
    message = (
        "This check verifies that new accounts are vended with suitable standards "
        "already defined.\n\n"
        "Consider the following factors:\n"
        "- Are new accounts vended with suitable standards?\n"
        "- Are the standards defined before account creation?\n"
        "- Are the standards consistently applied across all new accounts?"
    )
    prompt = "Are new accounts vended with suitable standards already defined?"

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "New accounts are vended with suitable standards already defined."
        ),
        fail_message=(
            "New accounts should be vended with suitable standards already defined."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_account_standards._CHECK_ID = CHECK_ID
check_account_standards._CHECK_NAME = CHECK_NAME
