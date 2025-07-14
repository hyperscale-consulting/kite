"""Check for root account monitoring and response procedures."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "root-account-monitoring"
CHECK_NAME = "Root Account Monitoring"


def check_root_account_monitoring() -> dict[str, Any]:
    """
    Check if there are systems and procedures in place to monitor for and respond to
    root account misuse.

    This is a manual check that prompts the user to verify:
    1. There are systems in place to monitor root account activity
    2. There are procedures to respond to suspicious root account activity
    3. These procedures are regularly tested and updated

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - procedures: str describing the procedures in place (if provided)
    """
    # Define the message and prompts
    message = (
        "This check verifies that there are systems and procedures in place to "
        "monitor for and respond to root account misuse.\n\n"
        "Consider the following factors:\n"
        "- Are there systems in place to monitor root account activity?\n"
        "- Are there procedures to respond to suspicious root account activity?\n"
        "- Are these procedures regularly tested and updated?"
    )
    prompt = (
        "Are there systems and procedures in place to monitor for and respond to "
        "root account misuse?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=("Root account monitoring and response procedures are in place."),
        fail_message=(
            "Root account monitoring and response procedures are not in place."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_root_account_monitoring._CHECK_ID = CHECK_ID
check_root_account_monitoring._CHECK_NAME = CHECK_NAME
