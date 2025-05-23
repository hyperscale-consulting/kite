"""Check if IAM delegation is done using permission boundaries."""

from typing import Dict, Any, List

from kite.data import (
    get_roles,
    get_policy_document,
    get_inline_policy_document,
    get_customer_managed_policies,
    get_iam_users,
    get_iam_groups,
)
from kite.helpers import get_account_ids_in_scope, manual_check


CHECK_ID = "delegate-iam-with-permission-boundaries"
CHECK_NAME = "Delegate IAM with Permission Boundaries"


def _has_permission_boundary_condition(policy_doc: Dict[str, Any]) -> bool:
    """
    Check if a policy document has a condition on permission boundaries.

    Args:
        policy_doc: The policy document to check

    Returns:
        bool: True if the policy has a condition on permission boundaries
    """
    if not isinstance(policy_doc, dict) or "Statement" not in policy_doc:
        return False

    statements = policy_doc["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        # Check for a condition on permission boundaries
        condition = statement.get("Condition", {})
        if not isinstance(condition, dict):
            continue

        # Check for StringEquals or ArnEquals conditions on aws:PermissionsBoundary
        for condition_type in ["StringEquals", "ArnEquals"]:
            if condition_type in condition:
                boundary_condition = condition[condition_type].get("aws:PermissionsBoundary")
                if boundary_condition:
                    return True

    return False


def check_delegate_iam_with_permission_boundaries() -> Dict[str, Any]:
    """
    Check if IAM delegation is done using permission boundaries.

    This check verifies that:
    1. There are policies (inline or attached) that allow IAM actions
    2. These policies have conditions on aws:PermissionsBoundary
    3. The conditions specify a valid permission boundary policy ARN

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - roles_with_delegation: List of roles with IAM delegation policies
    """
    # Track roles with IAM delegation policies
    entities_with_delegation: List[Dict[str, Any]] = []

    # Get in-scope accounts
    account_ids = get_account_ids_in_scope()

    # Check each account
    for account_id in account_ids:
        # Get all IAM entities in the account
        users = get_iam_users(account_id)
        groups = get_iam_groups(account_id)
        roles = get_roles(account_id)

        customer_policies = get_customer_managed_policies(account_id)

        for entity in users + groups + roles:
            has_iam_delegation = False
            delegation_policy_info = None

            # Check attached policies
            for policy in entity.get("AttachedPolicies", []):
                policy_arn = policy["PolicyArn"]
                # Check customer managed policies
                for customer_policy in customer_policies:
                    if customer_policy["Arn"] == policy_arn:
                        policy_doc = get_policy_document(account_id, policy_arn)
                        if policy_doc and _has_permission_boundary_condition(policy_doc):
                            has_iam_delegation = True
                            delegation_policy_info = {
                                "policy_name": customer_policy["Name"],
                                "policy_arn": policy_arn,
                                "policy_type": "customer_managed",
                            }
                            break
                    if has_iam_delegation:
                        break

            # Check inline policies
            if not has_iam_delegation:
                for policy_name in entity.get("InlinePolicyNames", []):
                    policy_doc = get_inline_policy_document(
                        account_id, entity["RoleName"], policy_name
                    )
                    if policy_doc and _has_permission_boundary_condition(policy_doc):
                        has_iam_delegation = True
                        delegation_policy_info = {
                            "policy_name": policy_name,
                            "policy_type": "inline",
                        }
                        break

            if has_iam_delegation and delegation_policy_info:
                entities_with_delegation.append({
                    "account_id": account_id,
                    "entity_name": entity["RoleName"],
                    "entity_arn": entity["Arn"],
                    **delegation_policy_info,
                })


    if not entities_with_delegation:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "No IAM entities found with IAM delegation policies. "
                    "Permission boundaries should be used to safely delegate IAM "
                    "administration to workload teams."
                )
            },
        }

    # Build message for manual check
    message = "IAM entities with IAM Delegation Policies:\n\n"
    if entities_with_delegation:
        for entity in entities_with_delegation:
            message += f"Account: {entity['account_id']}\n"
            message += f"Entity Name: {entity['entity_name']}\n"
            message += f"Entity ARN: {entity['entity_arn']}\n"
            if "policy_arn" in entity:
                message += f"Policy ARN: {entity['policy_arn']}\n"
            message += f"Policy Name: {entity['policy_name']}\n"
            message += f"Policy Type: {entity['policy_type']}\n\n"

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are permission boundaries used to safely delegate IAM administration "
            "to workload teams?"
        ),
        pass_message=(
            "Permission boundaries are used to safely delegate IAM administration "
            "to workload teams."
        ),
        fail_message=(
            "Permission boundaries should be used to safely delegate IAM "
            "administration to workload teams."
        ),
        default=False,
    )


check_delegate_iam_with_permission_boundaries._CHECK_ID = CHECK_ID
check_delegate_iam_with_permission_boundaries._CHECK_NAME = CHECK_NAME
