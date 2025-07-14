"""Check for regular penetration testing of security controls."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "perform-regular-pen-testing"
CHECK_NAME = "Perform Regular Penetration Testing"


def check_perform_regular_pen_testing() -> dict[str, Any]:
    """
    Check if regular penetration testing is performed to validate security controls.

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
        "This check verifies that regular penetration testing is performed to validate "
        "security controls.\n\n"
        "Consider the following factors:\n"
        "- Is penetration testing performed on a regular schedule?\n"
        "- Are findings from penetration tests tracked and remediated?\n"
        "- Are findings from penetration tests analysed to identify systemic issues to"
        " inform automated tests and developer training?\n"
        "- Are penetration test results reviewed and shared with relevant stakeholders?"
    )
    prompt = "Is regular penetration testing performed to validate security controls?"

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Regular penetration testing is performed to validate security controls."
        ),
        fail_message=(
            "Regular penetration testing should be performed to validate security "
            "controls."
        ),
        default=True,
    )

    return result


check_perform_regular_pen_testing._CHECK_ID = CHECK_ID
check_perform_regular_pen_testing._CHECK_NAME = CHECK_NAME
