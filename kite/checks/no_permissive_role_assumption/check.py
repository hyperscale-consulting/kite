"""Check for IAM policies that allow permissive role assumption."""

from typing import Dict, Any, List

from kite.helpers import get_prowler_output


CHECK_ID = "no-permissive-role-assumption"
CHECK_NAME = "No Permissive Role Assumption"


def check_no_permissive_role_assumption() -> Dict[str, Any]:
    """
    Check if IAM policies allow permissive role assumption.

    This check verifies that IAM policies do not allow permissive role assumption
    by checking Prowler results for the following check ID:
    - iam_no_custom_policy_permissive_role_assumption

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
    check_id = "iam_no_custom_policy_permissive_role_assumption"

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
                "No IAM policies were found that allow permissive role assumption."
                if passed
                else (
                    f"Found {len(failing_resources)} IAM policies that allow "
                    "permissive role assumption."
                )
            ),
            "failing_resources": failing_resources,
        },
    }


# Attach the check ID and name to the function
check_no_permissive_role_assumption._CHECK_ID = CHECK_ID
check_no_permissive_role_assumption._CHECK_NAME = CHECK_NAME
