"""Check for disallow root access keys SCP."""

import json
from typing import Any

from kite.data import get_organization

CHECK_ID = "root-access-keys-disallowed"
CHECK_NAME = "Root Access Keys Disallowed"


def check_root_access_keys_disallowed() -> dict[str, Any]:
    """
    Check if there is an effective SCP that disallows root access keys.

    This check verifies that:
    1. There is an SCP that denies the iam:CreateAccessKey action
    2. The SCP is either applied at the root OU level or at every OU in the level directly below the root
    3. The SCP either has no condition or has a condition that checks if the principal is the root user

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - ous_without_scp: List of OUs that don't have the required SCP (if applicable)
    """
    try:
        org = get_organization()
        if org is None:
            return {
                "check_id": CHECK_ID,
                "check_name": CHECK_NAME,
                "status": "FAIL",
                "details": {
                    "message": (
                        "AWS Organizations is not being used, so root access keys "
                        "disallow SCP cannot be assessed."
                    ),
                },
            }

        # Check root OU for root access keys disallow SCP
        root_scps = org.root.scps
        root_has_disallow_scp = False
        root_disallow_scp = None

        for scp in root_scps:
            try:
                content = json.loads(scp.content)
                if _is_root_access_keys_disallow_scp(content):
                    root_has_disallow_scp = True
                    root_disallow_scp = scp
                    break
            except json.JSONDecodeError:
                continue

        # If root has disallow SCP, we're good
        if root_has_disallow_scp:
            return {
                "check_id": CHECK_ID,
                "check_name": CHECK_NAME,
                "status": "PASS",
                "details": {
                    "message": (
                        "Root access keys disallow SCP is attached to the root OU."
                    ),
                    "scp": {
                        "id": root_disallow_scp.id,
                        "name": root_disallow_scp.name,
                        "arn": root_disallow_scp.arn,
                    },
                },
            }

        # Check top-level OUs for root access keys disallow SCP
        top_level_ous = org.root.child_ous
        ous_without_disallow_scp = []

        # If there's no disallow SCP on root and no top-level OUs, that's a fail
        if not top_level_ous:
            return {
                "check_id": CHECK_ID,
                "check_name": CHECK_NAME,
                "status": "FAIL",
                "details": {
                    "message": (
                        "Root access keys disallow SCP is not attached to the root OU "
                        "and there are no top-level OUs."
                    ),
                },
            }

        for ou in top_level_ous:
            ou_has_disallow_scp = False
            for scp in ou.scps:
                try:
                    content = json.loads(scp.content)
                    if _is_root_access_keys_disallow_scp(content):
                        ou_has_disallow_scp = True
                        break
                except json.JSONDecodeError:
                    continue

            if not ou_has_disallow_scp:
                ous_without_disallow_scp.append(ou.name)

        if ous_without_disallow_scp:
            return {
                "check_id": CHECK_ID,
                "check_name": CHECK_NAME,
                "status": "FAIL",
                "details": {
                    "message": (
                        "Root access keys disallow SCP is not attached to the root OU "
                        "or all top-level OUs. The following top-level OUs do not have "
                        "a root access keys disallow SCP: "
                    )
                    + ", ".join(ous_without_disallow_scp),
                    "ous_without_scp": ous_without_disallow_scp,
                },
            }

        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "Root access keys disallow SCP is attached to all top-level OUs."
                ),
            },
        }

    except Exception as e:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {
                "message": f"Error checking root access keys disallow SCP: {str(e)}",
            },
        }


def _is_root_access_keys_disallow_scp(content: dict[str, Any]) -> bool:
    """
    Check if an SCP effectively disallows root access keys.

    Args:
        content: The SCP content as a dictionary

    Returns:
        True if the SCP disallows root access keys
    """
    if not isinstance(content, dict) or "Statement" not in content:
        return False

    statements = content["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        # Check for a deny statement with iam:CreateAccessKey action
        if statement.get("Effect") == "Deny" and "Action" in statement:
            actions = statement["Action"]
            if not isinstance(actions, list):
                actions = [actions]

            # Check if the statement denies iam:CreateAccessKey
            if "iam:CreateAccessKey" in actions:
                # If there's no condition, it denies all CreateAccessKey actions
                if "Condition" not in statement:
                    return True

                # Check if the condition is for root user
                condition = statement["Condition"]

                # Check for ArnLike condition
                if (
                    "ArnLike" in condition
                    and "aws:PrincipalArn" in condition["ArnLike"]
                ):
                    principal_arns = condition["ArnLike"]["aws:PrincipalArn"]
                    if not isinstance(principal_arns, list):
                        principal_arns = [principal_arns]

                    # Check if any of the ARNs match the root user pattern
                    if any(arn == "arn:*:iam::*:root" for arn in principal_arns):
                        return True

                # Check for StringLike condition
                if (
                    "StringLike" in condition
                    and "aws:PrincipalArn" in condition["StringLike"]
                ):
                    principal_arns = condition["StringLike"]["aws:PrincipalArn"]
                    if not isinstance(principal_arns, list):
                        principal_arns = [principal_arns]

                    # Check if any of the ARNs match the root user pattern
                    if any(arn == "arn:*:iam::*:root" for arn in principal_arns):
                        return True

    return False


# Attach the check ID and name to the function
check_root_access_keys_disallowed._CHECK_ID = CHECK_ID
check_root_access_keys_disallowed._CHECK_NAME = CHECK_NAME
