"""Check for enabled RDS logging."""

from typing import Any

from kite.helpers import get_prowler_output

CHECK_ID = "rds-logging-enabled"
CHECK_NAME = "RDS Logging Enabled"


def check_rds_logging_enabled() -> dict[str, Any]:
    """
    Check if RDS logging is enabled.

    This check verifies that RDS logging is enabled by checking Prowler
    results for the following check ID:
    - rds_instance_integration_cloudwatch_logs

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - failing_resources: List of resources that failed the check
    """
    # Get Prowler results
    prowler_results = get_prowler_output()

    # The check ID we're interested in
    check_id = "rds_instance_integration_cloudwatch_logs"

    # Track failing resources
    failing_resources: list[dict[str, Any]] = []

    # Check results for the check ID
    if check_id in prowler_results:
        # Get results for this check ID
        results = prowler_results[check_id]

        # Add failing resources to the list
        for result in results:
            if result.status != "PASS":
                failing_resources.append(
                    {
                        "account_id": result.account_id,
                        "resource_uid": result.resource_uid,
                        "resource_name": result.resource_name,
                        "resource_details": result.resource_details,
                        "region": result.region,
                        "status": result.status,
                    }
                )

    # Determine if the check passed
    passed = len(failing_resources) == 0

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS" if passed else "FAIL",
        "details": {
            "message": (
                "All RDS instances have logging enabled."
                if passed
                else (
                    f"Found {len(failing_resources)} RDS instances without "
                    "logging enabled."
                )
            ),
            "failing_resources": failing_resources,
        },
    }


# Attach the check ID and name to the function
check_rds_logging_enabled._CHECK_ID = CHECK_ID
check_rds_logging_enabled._CHECK_NAME = CHECK_NAME
