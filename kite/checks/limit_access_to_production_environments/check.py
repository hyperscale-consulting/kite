"""Check for limiting access to production environments."""

import json
import os
from typing import Dict, Any, List

from kite.helpers import (
    get_account_ids_in_scope,
    manual_check,
)
from kite.data import get_roles, get_credentials_report
from kite.config import Config


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


def _save_identity_data(account_id: str, data: Dict[str, Any]) -> str:
    """
    Save identity data to a file in the data directory.

    Args:
        account_id: The AWS account ID
        data: The identity data to save

    Returns:
        The path to the saved file
    """
    # Create data directory if it doesn't exist
    os.makedirs(Config.get().data_dir, exist_ok=True)

    # Create account-specific directory
    account_dir = f"{Config.get().data_dir}/{account_id}"
    os.makedirs(account_dir, exist_ok=True)

    # Save data to file
    file_path = f"{account_dir}/human_accessible_identities.json"
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    return file_path


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
    saved_files: Dict[str, str] = {}

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

        # Save the data for this account
        if human_accessible_identities:
            file_path = _save_identity_data(
                account_id,
                {
                    "account_id": account_id,
                    "identities": [
                        identity for identity in human_accessible_identities
                        if identity["account_id"] == account_id
                    ]
                }
            )
            saved_files[account_id] = file_path

    # Build message for manual check
    message = "Identities that can be accessed by humans:\n\n"
    if human_accessible_identities:
        message += "Detailed information has been saved to the following files:\n"
        for account_id, file_path in saved_files.items():
            message += f"- {file_path}\n"
        message += "\nSummary of findings:\n"
        for account_id in account_ids:
            account_identities = [
                identity for identity in human_accessible_identities
                if identity["account_id"] == account_id
            ]
            if account_identities:
                message += f"\nAccount {account_id}:\n"
                for identity in account_identities:
                    message += f"- {identity['identity_type']}: {identity['name']}\n"
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
        result["details"]["saved_files"] = saved_files

    return result


check_limit_access_to_production_environments._CHECK_ID = CHECK_ID
check_limit_access_to_production_environments._CHECK_NAME = CHECK_NAME
