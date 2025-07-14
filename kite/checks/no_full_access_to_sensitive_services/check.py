"""Check for IAM policies that allow full access to sensitive services."""

from typing import Any

from kite.helpers import get_prowler_output

CHECK_ID = "no-full-access-to-sensitive-services"
CHECK_NAME = "No Full Access to Sensitive Services"


def check_no_full_access_to_sensitive_services() -> dict[str, Any]:
    """
    Check if IAM policies allow full access to sensitive services.

    This check verifies that IAM policies (both inline and managed) do not allow
    full access to sensitive services by checking Prowler results for the following
    check IDs:
    - iam_policy_no_full_access_to_cloudtrail
    - iam_inline_policy_no_full_access_to_cloudtrail
    - iam_policy_no_full_access_to_kms
    - iam_inline_policy_no_full_access_to_kms
    - iam_policy_cloudshell_admin_not_attached

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

    # The check IDs we're interested in
    check_ids = [
        "iam_policy_no_full_access_to_cloudtrail",
        "iam_inline_policy_no_full_access_to_cloudtrail",
        "iam_policy_no_full_access_to_kms",
        "iam_inline_policy_no_full_access_to_kms",
        "iam_policy_cloudshell_admin_not_attached",
    ]

    # Track failing resources
    failing_resources: list[dict[str, Any]] = []

    # Check results for each check ID
    for check_id in check_ids:
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
                            "check_id": check_id,
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
                "No IAM policies were found that allow full access to sensitive "
                "services."
                if passed
                else (
                    f"Found {len(failing_resources)} IAM policies that allow full "
                    "access to sensitive services."
                )
            ),
            "failing_resources": failing_resources,
        },
    }


# Attach the check ID and name to the function
check_no_full_access_to_sensitive_services._CHECK_ID = CHECK_ID
check_no_full_access_to_sensitive_services._CHECK_NAME = CHECK_NAME
