"""Check for Glue ETL jobs using detect sensitive data transform."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "detect-sensitive-data-transform"
CHECK_NAME = "Detect Sensitive Data Transform"


def check_detect_sensitive_data_transform() -> dict[str, Any]:
    """
    Check if the detect sensitive data transform is used in any Glue ETL jobs to
    detect and handle sensitive data.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=(
            "This check verifies that the Detect Sensitive Data transform is used "
            "in Glue ETL jobs to detect and handle sensitive data."
        ),
        prompt=(
            "Is the detect sensitive data transform used in any Glue ETL jobs to "
            "detect and handle sensitive data?"
        ),
        pass_message=(
            "The detect sensitive data transform is used in Glue ETL jobs to "
            "detect and handle sensitive data."
        ),
        fail_message=(
            "The detect sensitive data transform should be used in Glue ETL jobs "
            "to detect and handle sensitive data."
        ),
        default=True,
    )


check_detect_sensitive_data_transform._CHECK_ID = CHECK_ID
check_detect_sensitive_data_transform._CHECK_NAME = CHECK_NAME
