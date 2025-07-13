"""Check for restricted role access to secrets."""

import json
from typing import Dict, Any
from kite.helpers import (
    get_account_ids_in_scope,
    manual_check,
)
from kite.config import Config
from kite.data import get_role_by_arn, get_secrets


CHECK_ID = "restricted-role-for-secrets-access"
CHECK_NAME = "Restricted Role for Secrets Access"


def get_trust_policy(role_arn):
    role = get_role_by_arn(role_arn)
    if role:
        return role["AssumeRolePolicyDocument"]
    return None


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
    account_ids = get_account_ids_in_scope()
    config = Config.get()

    secrets_without_policy = []
    secrets_without_deny = []
    principals_found = {}

    for account_id in account_ids:
        for region in config.active_regions:
            secrets = get_secrets(account_id, region)

            for secret in secrets:
                if not secret.get("ResourcePolicy", {}):
                    secrets_without_policy.append(
                        {
                            "account_id": account_id,
                            "region": region,
                            "secret_name": secret["Name"],
                            "arn": secret["ARN"],
                        }
                    )
                    continue

                # Parse the resource policy
                policy = secret.get("ResourcePolicy", {})

                # Check for deny statements with principal conditions
                has_principal_deny = False
                for statement in policy.get("Statement", []):
                    if (
                        statement.get("Effect") == "Deny"
                        and statement.get("Principal") == "*"
                    ):
                        condition = statement.get("Condition", {})
                        for key in [
                            "StringNotEquals",
                            "ArnNotEquals",
                            "StringNotLike",
                            "ArnNotLike",
                        ]:
                            if key in condition:
                                for value in condition[key].values():
                                    if isinstance(value, list):
                                        for v in value:
                                            principals_found[v] = get_trust_policy(v)
                                    elif isinstance(value, str):
                                        principals_found[value] = get_trust_policy(
                                            value
                                        )
                                has_principal_deny = True

                if not has_principal_deny:
                    secrets_without_deny.append(
                        {
                            "account_id": account_id,
                            "region": region,
                            "secret_name": secret["Name"],
                            "arn": secret["ARN"],
                        }
                    )

    message = (
        "This check assesses whether secrets access is restricted to a dedicated "
        "role that can only be assumed by a small set of operational users.\n\n"
        "To do this, secrets should have resource policies that look something like this:\n\n"
        "{\n"
        '  "Statement": [\n'
        "    {\n"
        '      "Effect": "Allow",'
        '      "Principal": {"AWS": "arn:aws:iam::123456789012:role/SecretAdmin"}\n'
        "    },\n"
        "    {\n"
        '      "Effect": "Deny",\n'
        '      "Principal": "*",\n'
        '      "Action": "*",\n'
        '      "Condition": {\n'
        '        "StringNotEquals": {\n'
        '        "  aws:PrincipalArn": "arn:aws:iam::123456789012:role/SecretAdmin"\n'
        "        }\n"
        "    }\n"
        "  ]\n"
        "}\n\n"
    )

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
            message += "Secrets without deny statements:\n"
            for secret in secrets_without_deny:
                message += (
                    f"- {secret['secret_name']} in account {secret['account_id']} "
                    f"region {secret['region']}\n"
                )
            message += "\n"

    if principals_found:
        message += "Principals found in deny exception conditions:\n\n"
        for principal, trust_policy in principals_found.items():
            message += f"- {principal}\n"
            if trust_policy:
                message += "  Principals allowed to assume this role:\n"
                message += "\n".join(
                    [
                        f"  - {s['Principal']}"
                        for s in trust_policy.get("Statement", [])
                        if s.get("Effect") == "Allow"
                    ]
                )
            else:
                message += "  No trust policy found.\n"
            message += "\n"

    if not secrets_without_policy and not secrets_without_deny and not principals_found:
        return dict(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            status="PASS",
            details=dict(message="No secrets found in in-scope accounts."),
        )

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
            "Secret access should be restricted to specific roles with limited access."
        ),
        default=False,
    )

    # Add the details to the result
    if "details" in result:
        result["details"]["secrets_without_policy"] = secrets_without_policy
        result["details"]["secrets_without_deny"] = secrets_without_deny
        result["details"]["principals_found"] = list(principals_found)

    return result


check_restricted_role_for_secrets_access._CHECK_ID = CHECK_ID
check_restricted_role_for_secrets_access._CHECK_NAME = CHECK_NAME
