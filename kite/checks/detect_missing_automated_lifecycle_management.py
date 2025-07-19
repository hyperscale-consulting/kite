"""Check for detection of missing automated lifecycle management."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "detect-missing-automated-lifecycle-management"
CHECK_NAME = "Detect Missing Automated Lifecycle Management"


def check_detect_missing_automated_lifecycle_management() -> dict[str, Any]:
    """
    Check if there are config rules in place that detect and alert when automated
    lifecycle management is not turned on when it should be.

    This check asks the user to confirm that:
    1. Config rules are in place to detect missing lifecycle management
    2. Alerts are configured for when lifecycle management is missing
    3. Rules cover all relevant services (e.g., S3, DynamoDB, etc.)

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that config rules are in place to detect and alert "
        "when automated lifecycle management is not turned on when it should be."
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are there config rules in place that detect and alert when automated "
            "lifecycle management is not turned on when it should be?"
        ),
        pass_message=(
            "Config rules are in place to detect and alert when automated "
            "lifecycle management is not turned on when it should be."
        ),
        fail_message=(
            "Config rules should be in place to detect and alert when automated "
            "lifecycle management is not turned on when it should be."
        ),
        default=True,
    )


check_detect_missing_automated_lifecycle_management._CHECK_ID = CHECK_ID
check_detect_missing_automated_lifecycle_management._CHECK_NAME = CHECK_NAME
