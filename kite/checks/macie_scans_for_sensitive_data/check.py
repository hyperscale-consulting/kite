"""Check for Macie scanning of sensitive data."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "macie-scans-for-sensitive-data"
CHECK_NAME = "Macie Scans for Sensitive Data"


def check_macie_scans_for_sensitive_data() -> Dict[str, Any]:
    # TODO: Add permissions so we can do some automated support with this check.
    """
    Check if Macie is used to scan for sensitive data across workloads.

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
            "This check verifies that Macie is used to scan for sensitive data "
            "across workloads.\n\n"
            "Note: Data can be exported from data sources such as RDS and DynamoDB "
            "into an S3 bucket for scanning by Macie."
        ),
        prompt=(
            "Is Macie used to scan for sensitive data across workloads?"
        ),
        pass_message=(
            "Macie is used to scan for sensitive data across workloads."
        ),
        fail_message=(
            "Macie should be used to scan for sensitive data across workloads."
        ),
        default=True,
    )


check_macie_scans_for_sensitive_data._CHECK_ID = CHECK_ID
check_macie_scans_for_sensitive_data._CHECK_NAME = CHECK_NAME
