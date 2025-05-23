"""SCP prevents leaving organization check module."""

import json
from typing import List, Dict, Any

from kite.data import get_organization


CHECK_ID = "scp-prevents-leaving-org"
CHECK_NAME = "SCP Prevents Leaving Organization"


def check_scp_prevents_leaving_org() -> dict:
    """
    Check if there is an effective SCP that prevents leaving the organization.

    This check verifies that:
    1. There is an SCP that denies the organizations:LeaveOrganization action
    2. The SCP is attached to either the root OU or all top-level OUs

    Returns:
        A dictionary containing the finding for the SCP prevents leaving organization check.
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
                    "leaving organization cannot be assessed."
                ),
            },
        }

    # Check root OU for leave organization deny SCP
    root_scps = org.root.scps
    root_has_leave_deny = False
    root_leave_deny_scp = None

    for scp in root_scps:
        try:
            content = json.loads(scp.content)
            if _is_leave_deny_scp(content):
                root_has_leave_deny = True
                root_leave_deny_scp = scp
                break
        except json.JSONDecodeError:
            continue

    # If root has leave deny SCP, we're good
    if root_has_leave_deny:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "SCP preventing leaving organization is attached to the root OU."
                ),
                "scp": {
                    "id": root_leave_deny_scp.id,
                    "name": root_leave_deny_scp.name,
                    "arn": root_leave_deny_scp.arn,
                },
            },
        }

    # Check top-level OUs for leave deny SCP
    top_level_ous = org.root.child_ous
    ous_without_leave_deny = []

    # If there's no leave deny SCP on root and no top-level OUs, that's a fail
    if not top_level_ous:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "SCP preventing leaving organization is not attached to the "
                    "root OU and there are no top-level OUs."
                ),
            },
        }

    for ou in top_level_ous:
        ou_has_leave_deny = False
        for scp in ou.scps:
            try:
                content = json.loads(scp.content)
                if _is_leave_deny_scp(content):
                    ou_has_leave_deny = True
                    break
            except json.JSONDecodeError:
                continue

        if not ou_has_leave_deny:
            ous_without_leave_deny.append(ou.name)

    if ous_without_leave_deny:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "SCP preventing leaving organization is not attached to the "
                    "root OU or all top-level OUs. The following top-level OUs "
                    "do not have a leave deny SCP: "
                )
                + ", ".join(ous_without_leave_deny),
            },
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS",
        "details": {
            "message": (
                "SCP preventing leaving organization is attached to all "
                "top-level OUs."
            ),
        },
    }


def _is_leave_deny_scp(content: Dict[str, Any]) -> bool:
    """
    Check if an SCP effectively denies the organizations:LeaveOrganization action.

    Args:
        content: The SCP content as a dictionary

    Returns:
        True if the SCP denies the organizations:LeaveOrganization action
    """
    if not isinstance(content, dict) or "Statement" not in content:
        return False

    statements = content["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        # Check for a deny statement with organizations:LeaveOrganization action
        if (
            statement.get("Effect") == "Deny"
            and "Action" in statement
            and statement["Action"] == "organizations:LeaveOrganization"
            and statement.get("Resource") == "*"
        ):
            return True

    return False


# Attach the check ID and name to the function
check_scp_prevents_leaving_org._CHECK_ID = CHECK_ID
check_scp_prevents_leaving_org._CHECK_NAME = CHECK_NAME
