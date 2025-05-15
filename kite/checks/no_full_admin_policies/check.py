"""Check for customer managed policies with full admin privileges using Prowler."""

from typing import Dict, Any
from collections import defaultdict

from kite.helpers import get_prowler_output


CHECK_ID = "no-full-admin-policies"
CHECK_NAME = "No Full Admin Policies"
PROWLER_CHECK_ID = "iam_customer_attached_policy_no_administrative_privileges"


def check_no_full_admin_policies() -> Dict[str, Any]:
    """
    Check if there are any customer managed policies with administrative privileges.

    This check uses the prowler check results for the customer managed policies
    check to identify policies that have full administrative privileges.

    Returns:
        Dict containing the check results.
    """
    # Get all prowler check results
    prowler_results = get_prowler_output()

    # Get the specific check results for administrative privileges
    admin_policies_results = prowler_results.get(PROWLER_CHECK_ID, [])

    # Group failed checks by account
    failed_policies = defaultdict(list)
    for result in admin_policies_results:
        if result.status != "PASS":
            failed_policies[result.account_id].append({
                "PolicyName": result.resource_name,
                "ResourceId": result.resource_uid,
                "Details": result.resource_details,
            })

    # Determine the status based on findings
    has_admin_policies = bool(failed_policies)

    # Create the result message
    if has_admin_policies:
        message = "The following customer managed policies have administrative privileges:\n\n"
        for account_id, policies in failed_policies.items():
            message += f"Account {account_id}:\n"
            for policy in policies:
                message += f"- {policy['PolicyName']} ({policy['ResourceId']})\n"
                if policy['Details']:
                    message += f"  Details: {policy['Details']}\n"

        message += "\nPolicies with administrative privileges should be avoided as they "
        message += "grant excessive permissions."
        message += "\nConsider using more granular permissions that follow the principle "
        message += "of least privilege."
    else:
        message = "No customer managed policies with administrative privileges were found."

    # Create the result
    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL" if has_admin_policies else "PASS",
        "details": {
            "message": message,
            "failed_policies": dict(failed_policies),
            "prowler_check_id": PROWLER_CHECK_ID,
        }
    }


# Attach the check ID and name to the function
check_no_full_admin_policies._CHECK_ID = CHECK_ID
check_no_full_admin_policies._CHECK_NAME = CHECK_NAME
