"""Check for IAM policies that allow privilege escalation."""

from typing import Dict, Any, List

from kite.helpers import get_prowler_output


CHECK_ID = "no-policy-allows-privilege-escalation"
CHECK_NAME = "No IAM Policy Allows Privilege Escalation"


def check_no_policy_allows_privilege_escalation() -> Dict[str, Any]:
    """
    Check if IAM policies allow privilege escalation.

    This check verifies that IAM policies (both inline and managed) do not allow
    privilege escalation by checking Prowler results for the following check IDs:
    - iam_inline_policy_allows_privilege_escalation
    - iam_policy_allows_privilege_escalation

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - failing_resources: List of resources that failed the check
    """
    try:
        # Get Prowler results
        prowler_results = get_prowler_output()

        # The check IDs we're interested in
        check_ids = [
            "iam_inline_policy_allows_privilege_escalation",
            "iam_policy_allows_privilege_escalation"
        ]

        # Track failing resources
        failing_resources: List[Dict[str, Any]] = []

        # Check results for each check ID
        for check_id in check_ids:
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
                    "No IAM policies were found that allow privilege escalation."
                    if passed
                    else (
                        f"Found {len(failing_resources)} IAM policies that allow "
                        "privilege escalation."
                    )
                ),
                "failing_resources": failing_resources,
            },
        }

    except Exception as e:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {
                "message": (
                    "Error checking for IAM policies that allow privilege escalation: "
                    f"{str(e)}"
                ),
            },
        }


# Attach the check ID and name to the function
check_no_policy_allows_privilege_escalation._CHECK_ID = CHECK_ID
check_no_policy_allows_privilege_escalation._CHECK_NAME = CHECK_NAME
