"""Check for policies with administrative privileges using Prowler."""

from collections import defaultdict
from typing import Any

from kite.helpers import get_prowler_output

CHECK_ID = "no-full-admin-policies"
CHECK_NAME = "No Administrative Privilege Policies"

# List of Prowler check IDs that identify policies with administrative privileges
PROWLER_CHECK_IDS = [
    "iam_customer_attached_policy_no_administrative_privileges",
    "iam_aws_attached_policy_no_administrative_privileges",
    "iam_customer_unattached_policy_no_administrative_privileges",
    "iam_inline_policy_no_administrative_privileges",
]


def check_no_full_admin_policies() -> dict[str, Any]:
    """
    Check if there are any policies with administrative privileges.

    This check uses multiple Prowler check results to identify policies
    that have administrative privileges, including:
    - Customer managed attached policies
    - AWS managed attached policies
    - Customer managed unattached policies
    - Inline policies

    Returns:
        Dict containing the check results.
    """
    # Get all prowler check results
    prowler_results = get_prowler_output()

    # Group failed checks by account and check type
    failed_policies = defaultdict(lambda: defaultdict(list))
    checks_with_findings = set()

    # Process results from each check
    for check_id in PROWLER_CHECK_IDS:
        check_results = prowler_results.get(check_id, [])

        for result in check_results:
            if result.status != "PASS":
                account_id = result.account_id
                failed_policies[account_id][check_id].append(
                    {
                        "PolicyName": result.resource_name,
                        "ResourceId": result.resource_uid,
                        "Details": result.resource_details,
                    }
                )

                # Track which checks found issues
                checks_with_findings.add(check_id)

    # Determine the status based on findings
    has_admin_policies = bool(failed_policies)

    # Create the result message
    if has_admin_policies:
        message = "The following policies have administrative privileges:\n\n"

        # Map check IDs to friendly names for display
        check_friendly_names = {
            "iam_customer_attached_policy_no_administrative_privileges": "Customer Managed Attached Policies",
            "iam_aws_attached_policy_no_administrative_privileges": "AWS Managed Attached Policies",
            "iam_customer_unattached_policy_no_administrative_privileges": "Customer Managed Unattached Policies",
            "iam_inline_policy_no_administrative_privileges": "Inline Policies",
        }

        # Process results by account
        for account_id, account_results in failed_policies.items():
            message += f"Account {account_id}:\n"

            # Process results by check type
            for check_id, policies in account_results.items():
                check_name = check_friendly_names.get(check_id, check_id)
                message += f"  {check_name}:\n"

                # List each policy with its details
                for policy in policies:
                    message += f"  - {policy['PolicyName']} ({policy['ResourceId']})\n"
                    if policy["Details"]:
                        message += f"    Details: {policy['Details']}\n"

            message += "\n"

        message += "Policies with administrative privileges should be avoided as "
        message += "they grant excessive permissions.\n"
        message += "Consider using more granular permissions that follow the "
        message += "principle of least privilege."
    else:
        message = "No policies with administrative privileges were found."

    # Convert the nested defaultdict to a regular dict
    converted_policies = {}
    for account_id, account_results in failed_policies.items():
        converted_policies[account_id] = dict(account_results)

    # Create the result
    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL" if has_admin_policies else "PASS",
        "details": {
            "message": message,
            "failed_policies": converted_policies,
            "prowler_check_ids": PROWLER_CHECK_IDS,
            "checks_with_findings": list(checks_with_findings),
        },
    }


# Attach the check ID and name to the function
check_no_full_admin_policies._CHECK_ID = CHECK_ID
check_no_full_admin_policies._CHECK_NAME = CHECK_NAME
