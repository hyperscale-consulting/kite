"""Check for customer managed policies with full admin privileges."""

from typing import Dict, Any, List

from kite.helpers import (
    get_account_ids_in_scope,
    get_customer_managed_policies,
    get_policy_document,
)


CHECK_ID = "no-full-admin-policies"
CHECK_NAME = "No Full Admin Policies"


def has_wildcard_admin_permissions(policy_document: Dict[str, Any]) -> bool:
    """
    Check if a policy document contains a statement with full admin permissions.

    Full admin permissions are defined as:
    - Effect: "Allow"
    - Action: "*"
    - Resource: "*"

    Args:
        policy_document: The policy document to check

    Returns:
        True if the policy has full admin permissions, False otherwise
    """
    if not policy_document:
        return False

    # Get all statements in the policy
    statements = policy_document.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        # Check if this statement has full admin permissions
        if statement.get("Effect") == "Allow":
            # Check Action field
            action = statement.get("Action", [])
            if action == "*" or (isinstance(action, list) and "*" in action):
                # Check Resource field
                resource = statement.get("Resource", [])
                if resource == "*" or (isinstance(resource, list) and "*" in resource):
                    return True

    return False


def check_no_full_admin_policies() -> Dict[str, Any]:
    """
    Check if there are any customer managed policies with full admin permissions.

    This check:
    1. Gets all customer managed policies for each in-scope account
    2. For each policy, gets the policy document
    3. Checks if the policy document contains a statement with full admin permissions
    4. Returns any policies with full admin permissions

    Returns:
        Dict containing the check results.
    """
    # Get in-scope accounts
    account_ids = get_account_ids_in_scope()

    # Track policies with full admin permissions
    full_admin_policies: Dict[str, List[Dict[str, Any]]] = {}

    # Check each account
    for account_id in account_ids:
        # Get all customer managed policies
        policies = get_customer_managed_policies(account_id)

        # Check each policy
        for policy in policies:
            policy_arn = policy.get("Arn", "")
            policy_name = policy.get("PolicyName", "Unknown")

            # Get the policy document
            policy_document = get_policy_document(account_id, policy_arn)

            # Check if the policy has full admin permissions
            if has_wildcard_admin_permissions(policy_document):
                if account_id not in full_admin_policies:
                    full_admin_policies[account_id] = []

                full_admin_policies[account_id].append({
                    "PolicyName": policy_name,
                    "PolicyArn": policy_arn
                })

    # Determine the status based on findings
    has_full_admin = any(full_admin_policies.values())

    # Create the result message
    if has_full_admin:
        message = "The following customer managed policies have full admin permissions:\n\n"
        for account_id, policies in full_admin_policies.items():
            message += f"Account {account_id}:\n"
            for policy in policies:
                message += f"- {policy['PolicyName']} ({policy['PolicyArn']})\n"

        message += "\nPolicies with full admin permissions (Action: *, Resource: *) should be avoided as they grant excessive privileges."
        message += "\nConsider using more granular permissions that follow the principle of least privilege."
    else:
        message = "No customer managed policies with full admin permissions were found."

    # Create the result
    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL" if has_full_admin else "PASS",
        "details": {
            "message": message,
            "full_admin_policies": full_admin_policies
        }
    }


# Attach the check ID and name to the function
check_no_full_admin_policies._CHECK_ID = CHECK_ID
check_no_full_admin_policies._CHECK_NAME = CHECK_NAME
