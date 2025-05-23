"""SCP prevents common admin role changes check module."""

import json
from typing import Dict, Any

from kite.data import get_organization


CHECK_ID = "scp-prevents-common-admin-role-changes"
CHECK_NAME = "SCP Prevents Common Admin Role Changes"


def check_scp_prevents_common_admin_role_changes() -> dict:
    """
    Check if there is an effective SCP that prevents changes to common admin roles.

    This check verifies that:
    1. There is an SCP that denies the following IAM actions:
       - iam:UpdateRole
       - iam:DeleteRolePermissionBoundary
       - iam:AttachRolePolicy
       - iam:PutRolePermissionsBoundary
       - iam:PutRolePolicy
       - iam:UpdateAssumeRolePolicy
    2. The SCP is attached to either the root OU or all top-level OUs
    3. The SCP targets a specific role ARN pattern (arn:aws:iam::*:role/*)

    Returns:
        A dictionary containing the finding for the SCP prevents common admin role
        changes check.
    """

    org = get_organization()
    if org is None:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "AWS Organizations is not being used, so SCP preventing "
                    "common admin role changes cannot be assessed."
                ),
            },
        }

    # Check root OU for admin role deny SCP
    root_scps = org.root.scps
    root_has_admin_deny = False
    root_admin_deny_scp = None

    for scp in root_scps:
        try:
            content = json.loads(scp.content)
            if _is_admin_role_deny_scp(content):
                root_has_admin_deny = True
                root_admin_deny_scp = scp
                break
        except json.JSONDecodeError:
            continue

    # If root has admin deny SCP, we're good
    if root_has_admin_deny:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "SCP preventing common admin role changes is attached to "
                    "the root OU."
                ),
                "scp": {
                    "id": root_admin_deny_scp.id,
                    "name": root_admin_deny_scp.name,
                    "arn": root_admin_deny_scp.arn,
                },
            },
        }

    # Check top-level OUs for admin deny SCP
    top_level_ous = org.root.child_ous
    ous_without_admin_deny = []

    # If there's no admin deny SCP on root and no top-level OUs, that's a fail
    if not top_level_ous:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "SCP preventing common admin role changes is not attached "
                    "to the root OU and there are no top-level OUs."
                ),
            },
        }

    for ou in top_level_ous:
        ou_has_admin_deny = False
        for scp in ou.scps:
            try:
                content = json.loads(scp.content)
                if _is_admin_role_deny_scp(content):
                    ou_has_admin_deny = True
                    break
            except json.JSONDecodeError:
                continue

        if not ou_has_admin_deny:
            ous_without_admin_deny.append(ou.name)

    if ous_without_admin_deny:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "SCP preventing common admin role changes is not attached "
                    "to the root OU or all top-level OUs. The following "
                    "top-level OUs do not have an admin role deny SCP: "
                )
                + ", ".join(ous_without_admin_deny),
            },
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS",
        "details": {
            "message": (
                "SCP preventing common admin role changes is attached to all "
                "top-level OUs."
            ),
        },
    }


def _is_admin_role_deny_scp(content: Dict[str, Any]) -> bool:
    """
    Check if an SCP effectively denies changes to common admin roles.

    Args:
        content: The SCP content as a dictionary

    Returns:
        True if the SCP denies the required IAM actions for a specific role
    """
    if not isinstance(content, dict) or "Statement" not in content:
        return False

    statements = content["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    required_actions = {
        "iam:UpdateRole",
        "iam:DeleteRolePermissionBoundary",
        "iam:AttachRolePolicy",
        "iam:PutRolePermissionsBoundary",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
    }

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        # Check for a deny statement with the required IAM actions
        if (
            statement.get("Effect") == "Deny"
            and "Action" in statement
            and "Resource" in statement
        ):
            actions = statement["Action"]
            if not isinstance(actions, list):
                actions = [actions]

            # Check if all required actions are present
            if not all(action in actions for action in required_actions):
                continue

            # Check if the resource matches the role ARN pattern
            resources = statement["Resource"]
            if not isinstance(resources, list):
                resources = [resources]

            for resource in resources:
                if (
                    isinstance(resource, str)
                    and resource.startswith("arn:aws:iam::*:role/")
                ):
                    return True

    return False


# Attach the check ID and name to the function
check_scp_prevents_common_admin_role_changes._CHECK_ID = CHECK_ID
check_scp_prevents_common_admin_role_changes._CHECK_NAME = CHECK_NAME
