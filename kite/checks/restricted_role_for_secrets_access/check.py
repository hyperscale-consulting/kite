"""Check for restricted role access to secrets."""

import json
from typing import Dict, Any
from kite.helpers import (
    get_account_ids_in_scope,
    get_secrets,
    manual_check,
    assume_role,
)
from kite.config import Config


CHECK_ID = "restricted-role-for-secrets-access"
CHECK_NAME = "Restricted Role for Secrets Access"


def check_restricted_role_for_secrets_access() -> Dict[str, Any]:
    """
    Check if secrets access is restricted to specific roles with limited access.

    This check:
    1. Lists secrets without resource policies or deny statements
    2. Lists principals from deny conditions in resource policies

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - secrets_without_policy: List of secrets without resource policies
                - secrets_without_deny: List of secrets without role-based deny statements
                - principals_found: List of principals from deny conditions
    """
    try:
        # Get all account IDs in scope
        account_ids = get_account_ids_in_scope()
        config = Config.get()

        # Track secrets without policies and without deny statements
        secrets_without_policy = []
        secrets_without_deny = []
        principals_found = set()

        # Check each account and region
        for account_id in account_ids:
            for region in config.active_regions:
                secrets = get_secrets(account_id, region)

                for secret in secrets:
                    if not secret.resource_policy:
                        secrets_without_policy.append({
                            "account_id": account_id,
                            "region": region,
                            "secret_name": secret.name,
                            "arn": secret.arn
                        })
                        continue

                    # Parse the resource policy
                    policy = json.loads(secret.resource_policy)

                    # Check for deny statements with principal conditions
                    has_principal_deny = False
                    for statement in policy.get("Statement", []):
                        if statement.get("Effect") == "Deny":
                            condition = statement.get("Condition", {})
                            for key in ["StringNotEquals", "ArnNotEquals",
                                        "StringNotLike", "ArnNotLike"]:
                                if key in condition:
                                    for value in condition[key].values():
                                        if isinstance(value, list):
                                            for v in value:
                                                principals_found.add(v)
                                        elif isinstance(value, str):
                                            principals_found.add(value)
                                    has_principal_deny = True

                    if not has_principal_deny:
                        secrets_without_deny.append({
                            "account_id": account_id,
                            "region": region,
                            "secret_name": secret.name,
                            "arn": secret.arn
                        })

        # Build the message
        message = ""

        if secrets_without_policy or secrets_without_deny:
            message += "Secrets without proper access restrictions:\n\n"

            if secrets_without_policy:
                message += "Secrets without resource policies:\n"
                for secret in secrets_without_policy:
                    message += (
                        f"- {secret['secret_name']} in account {secret['account_id']} "
                        f"region {secret['region']}\n"
                    )
                message += "\n"

            if secrets_without_deny:
                message += "Secrets without principal-based deny statements:\n"
                for secret in secrets_without_deny:
                    message += (
                        f"- {secret['secret_name']} in account {secret['account_id']} "
                        f"region {secret['region']}\n"
                    )
                message += "\n"

        if principals_found:
            message += "Principals found in deny conditions:\n\n"
            for principal in principals_found:
                message += f"- {principal}\n"
                if ":role/" in principal:
                    try:
                        account_id = principal.split(":")[4]
                        role_name = principal.split("/")[-1]
                        session = assume_role(account_id)
                        iam_client = session.client("iam")
                        policy = iam_client.get_role(
                            RoleName=role_name
                        )["Role"]["AssumeRolePolicyDocument"]
                        message += "  Assume role policy:\n"
                        message += json.dumps(policy, indent=2) + "\n"
                    except Exception as e:
                        message += f"  Could not get assume role policy: {str(e)}\n"
                message += "\n"

        if not message:
            message = "No secrets found in in-scope accounts."

        result = manual_check(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            message=message,
            prompt=(
                "Is human exposure to secrets restricted to a dedicated role that can "
                "only be assumed by a small set of operational users?"
            ),
            pass_message=(
                "Secret access restrictions are appropriate for this environment."
            ),
            fail_message=(
                "Secret access should be restricted to specific roles with limited "
                "access."
            ),
            default=False,
        )

        # Add the details to the result
        if "details" in result:
            result["details"]["secrets_without_policy"] = secrets_without_policy
            result["details"]["secrets_without_deny"] = secrets_without_deny
            result["details"]["principals_found"] = list(principals_found)

        return result

    except Exception as e:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {
                "message": f"Error checking restricted role access: {str(e)}",
            },
        }


check_restricted_role_for_secrets_access._CHECK_ID = CHECK_ID
check_restricted_role_for_secrets_access._CHECK_NAME = CHECK_NAME
