"""Check for disabled S3 bucket ACLs."""

from typing import Any

from kite.helpers import get_prowler_output

CHECK_ID = "s3-bucket-acl-disabled"
CHECK_NAME = "S3 Bucket ACL Disabled"


def check_s3_bucket_acl_disabled() -> dict[str, Any]:
    """
    Check if S3 bucket ACLs are disabled.

    This check verifies that S3 bucket ACLs are disabled by checking Prowler
    results for the following check ID:
    - s3_bucket_acl_prohibited

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
    check_id = "s3_bucket_acl_prohibited"

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
                "All S3 buckets have ACLs disabled."
                if passed
                else (f"Found {len(failing_resources)} S3 buckets with ACLs enabled.")
            ),
            "failing_resources": failing_resources,
        },
    }


# Attach the check ID and name to the function
check_s3_bucket_acl_disabled._CHECK_ID = CHECK_ID
check_s3_bucket_acl_disabled._CHECK_NAME = CHECK_NAME
