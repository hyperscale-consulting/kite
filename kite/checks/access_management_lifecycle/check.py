"""Check if access management lifecycle process is defined and documented."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "access-management-lifecycle-defined"
CHECK_NAME = "Access Management Lifecycle Process is Defined and Documented"


def check_access_management_lifecycle() -> Dict[str, Any]:
    """
    Check if access management lifecycle process is defined and documented.

    This check verifies that:
    1. There is a defined process for granting initial access
    2. There is a defined process for periodic access reviews
    3. There is a defined process for offboarding

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "Please consider the following:\n\n"
        "- Is the access management lifecycle process clearly defined and documented?\n"
        "- Does it include procedures for granting initial access?\n"
        "- Does it include procedures for periodic access reviews?\n"
        "- Does it include procedures for offboarding?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is there a defined and documented process for managing user access throughout "
            "the user lifecycle?"
        ),
        pass_message=(
            "Access management lifecycle process is defined and documented."
        ),
        fail_message=(
            "Access management lifecycle process should be defined and documented."
        ),
        default=False,
    )


check_access_management_lifecycle._CHECK_ID = CHECK_ID
check_access_management_lifecycle._CHECK_NAME = CHECK_NAME
