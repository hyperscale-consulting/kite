"""Check for scanning sensitive data in development environments."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "scan-for-sensitive-data-in-dev"
CHECK_NAME = "Scan for Sensitive Data in Development"


def check_scan_for_sensitive_data_in_dev() -> dict[str, Any]:
    """
    Check if tools are used to automatically scan data for sensitivity while
    workloads are in development to alert when sensitive data is unexpected and
    prevent further deployment.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    # TODO: Add permissions so we can do some automated support with this check.
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=(
            "This check verifies that tools are used to automatically scan data "
            "for sensitivity while workloads are in development.\n\n"
            "Consider the following factors:\n"
            "- Are tools used to scan for sensitive data in development?\n"
            "- Are alerts configured for unexpected sensitive data?\n"
            "- Is deployment prevented when sensitive data is detected?\n"
            "- Do the scans align with your data classification scheme?"
        ),
        prompt=(
            "Are tools used to automatically scan data for sensitivity while "
            "workloads are in development to alert when sensitive data is "
            "unexpected and prevent further deployment?"
        ),
        pass_message=(
            "Tools are used to automatically scan data for sensitivity while "
            "workloads are in development."
        ),
        fail_message=(
            "Tools should be used to automatically scan data for sensitivity "
            "while workloads are in development."
        ),
        default=True,
    )


check_scan_for_sensitive_data_in_dev._CHECK_ID = CHECK_ID
check_scan_for_sensitive_data_in_dev._CHECK_NAME = CHECK_NAME
