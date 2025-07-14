"""Check for periodic testing of root user access."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "root-access-testing"
CHECK_NAME = "Root Access Testing"


def check_root_access_testing() -> dict[str, Any]:
    """
    Check if root user access is periodically tested to ensure it is functioning in
    emergency situations.

    This is a manual check that prompts the user to verify:
    1. Root user access is tested on a regular schedule
    2. The testing includes both password and MFA device verification
    3. The testing process is documented and includes emergency procedures

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
        "This check verifies that root user access is periodically tested to ensure "
        "it is functioning in emergency situations.\n\n"
        "Consider the following factors:\n"
        "- Is root user access tested on a regular schedule?\n"
        "- Does the testing include both password and MFA device verification?\n"
        "- Is the testing process documented and include emergency procedures?"
    )
    prompt = (
        "Is root user access periodically tested to ensure it is functioning in "
        "emergency situations?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Root user access is periodically tested to ensure it is functioning in "
            "emergency situations."
        ),
        fail_message=("Root user access testing procedures need improvement."),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_root_access_testing._CHECK_ID = CHECK_ID
check_root_access_testing._CHECK_NAME = CHECK_NAME
