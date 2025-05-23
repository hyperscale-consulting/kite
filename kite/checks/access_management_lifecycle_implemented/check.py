"""Check if access management lifecycle process is effectively implemented."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "access-management-lifecycle-implemented"
CHECK_NAME = "Access Management Lifecycle Process is Effectively Implemented"


def check_access_management_lifecycle_implemented() -> Dict[str, Any]:
    """
    Check if access management lifecycle process is effectively implemented.

    This check verifies that:
    1. Regular access reviews are being conducted
    2. Access revocation is prompt and effective
    3. There is a process for continuous improvement

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
        "- Are regular access reviews being conducted as scheduled?\n"
        "- Is access revoked promptly when no longer needed?\n"
        "- Is there a process to identify and implement improvements?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is the access management lifecycle process effectively implemented "
            "and followed?"
        ),
        pass_message=(
            "Access management lifecycle process is effectively implemented."
        ),
        fail_message=(
            "Access management lifecycle process should be effectively implemented."
        ),
        default=False,
    )


check_access_management_lifecycle_implemented._CHECK_ID = CHECK_ID
check_access_management_lifecycle_implemented._CHECK_NAME = CHECK_NAME
