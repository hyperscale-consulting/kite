"""Check for limiting access to production environments."""

import json
from typing import Dict, Any, List

from kite.helpers import (
    get_account_ids_in_scope,
    manual_check,
)
from kite.data import get_roles, get_credentials_report


CHECK_ID = "limit-access-to-prod"
CHECK_NAME = "Limit Access to Production Environments"


def _is_human_principal(principal: str) -> bool:
    """
    Check if a principal represents a human user.

    Args:
        principal: The principal ARN or identifier to check

    Returns:
        bool: True if the principal represents a human user
    """
    # Check for SAML provider
    if ":saml-provider/" in principal:
        return True

    # Check for IAM user
    if ":user/" in principal:
        return True

    # Check for AWS account root
    if principal.endswith(":root"):
        return True

    return False


def check_limit_access_to_production_environments() -> Dict[str, Any]:
    """
    Check if access to production environments is limited to specific tasks.

    This check:
    1. Identifies IAM identities (users and roles) that can be assumed by humans
    2. For each identity, shows:
       - The identity's name and ARN
       - The trust policy (for roles) or attached policies
       - Any conditions on the access
    3. Asks the user to verify:
       - Users are only granted access to production environments for specific tasks
       - Access is revoked as soon as the specific tasks are completed

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - human_accessible_identities: List of identities that can be accessed by humans
    """
    # Track identities that can be accessed by humans
    human_accessible_identities: List[Dict[str, Any]] = []

    # Get in-scope accounts
    account_ids = get_account_ids_in_scope()

    # Check each account
    for account_id in account_ids:
        # Get all roles in the account
        roles = get_roles(account_id)

        # Check each role's trust policy
        for role in roles:
            has_human_principal = False
            trust_policy = role.get("AssumeRolePolicyDocument", {})

            # Check each statement in the trust policy
            for statement in trust_policy.get("Statement", []):
                if statement.get("Effect") == "Allow":
                    principals = statement.get("Principal", {})
                    if isinstance(principals, dict):
                        for principal_type, principal_value in principals.items():
                            if isinstance(principal_value, list):
                                for principal in principal_value:
                                    if _is_human_principal(principal):
                                        has_human_principal = True
                                        break
                            elif isinstance(principal_value, str):
                                if _is_human_principal(principal_value):
                                    has_human_principal = True
                                    break

            if has_human_principal:
                human_accessible_identities.append({
                    "account_id": account_id,
                    "identity_type": "role",
                    "name": role["RoleName"],
                    "arn": role["Arn"],
                    "trust_policy": trust_policy,
                })

        # Get credentials report to check IAM users
        report = get_credentials_report(account_id)
        for user in report["users"]:
            if user.get("password_enabled", "false").lower() == "true":
                human_accessible_identities.append({
                    "account_id": account_id,
                    "identity_type": "user",
                    "name": user["user"],
                    "arn": (
                        f"arn:aws:iam::{account_id}:user/{user['user']}"
                    ),
                })

    # Build message for manual check
    message = "Identities that can be accessed by humans:\n\n"
    if human_accessible_identities:
        for identity in human_accessible_identities:
            message += f"Account: {identity['account_id']}\n"
            message += f"Type: {identity['identity_type']}\n"
            message += f"Name: {identity['name']}\n"
            message += f"ARN: {identity['arn']}\n"

            if identity['identity_type'] == 'role':
                message += "Trust Policy:\n"
                message += f"{json.dumps(identity['trust_policy'], indent=2)}\n"

            message += "Attached Policies:\n"
            for policy in identity['attached_policies']:
                message += f"- {policy}\n"
            message += "\n"
    else:
        message += "No identities found that can be accessed by humans.\n"

    # Perform manual check
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "For each identity that can be accessed by humans:\n"
            "1. Are users only granted access to production environments for specific "
            "tasks with a valid use case?\n"
            "2. Is access revoked as soon as the specific tasks are completed?"
        ),
        pass_message=(
            "Access to production environments is appropriately limited to specific tasks "
            "and revoked when no longer needed."
        ),
        fail_message=(
            "Access to production environments should be limited to specific tasks and "
            "revoked when no longer needed."
        ),
        default=False,
    )

    # Add the details to the result
    if "details" in result:
        result["details"]["human_accessible_identities"] = human_accessible_identities

    return result


check_limit_access_to_production_environments._CHECK_ID = CHECK_ID
check_limit_access_to_production_environments._CHECK_NAME = CHECK_NAME
