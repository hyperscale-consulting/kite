"""Check for cross-service confused deputy prevention in IAM roles."""

from typing import Dict, Any, List

from kite.helpers import get_prowler_output


CHECK_ID = "cross-service-confused-deputy-protection"
CHECK_NAME = "Cross-Service Confused Deputy Protection"


def check_cross_service_confused_deputy_protection() -> Dict[str, Any]:
    """
    Check if IAM roles have cross-service confused deputy prevention.

    This check verifies that IAM roles have proper cross-service confused deputy
    prevention by checking Prowler results for the check ID:
    - iam_role_cross_service_confused_deputy_prevention

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
    check_id = "iam_role_cross_service_confused_deputy_prevention"

    # Track failing resources
    failing_resources: List[Dict[str, Any]] = []

    # Check results for the check ID
    if check_id in prowler_results:
        # Get results for this check ID
        results = prowler_results[check_id]

        # Add failing resources to the list
        for result in results:
            if result.status != "PASS":
                failing_resources.append({
                    "account_id": result.account_id,
                    "resource_uid": result.resource_uid,
                    "resource_name": result.resource_name,
                    "resource_details": result.resource_details,
                    "region": result.region,
                    "check_id": check_id,
                    "status": result.status
                })

    # Determine if the check passed
    passed = len(failing_resources) == 0

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS" if passed else "FAIL",
        "details": {
            "message": (
                "All IAM roles have proper cross-service confused deputy prevention."
                if passed
                else (
                    f"Found {len(failing_resources)} IAM roles without proper "
                    "cross-service confused deputy prevention."
                )
            ),
            "failing_resources": failing_resources,
        },
    }


# Attach the check ID and name to the function
check_cross_service_confused_deputy_protection._CHECK_ID = CHECK_ID
check_cross_service_confused_deputy_protection._CHECK_NAME = CHECK_NAME
