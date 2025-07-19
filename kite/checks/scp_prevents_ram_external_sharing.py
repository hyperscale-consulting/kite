"""SCP prevents RAM external sharing check module."""

import json
from typing import Any

from kite.data import get_organization

CHECK_ID = "scp-prevents-ram-external-sharing"
CHECK_NAME = "SCP Prevents RAM External Sharing"


def check_scp_prevents_ram_external_sharing() -> dict:
    """
    Check if there is an effective SCP that prevents external sharing in RAM.

    This check verifies that:
    1. There is an SCP that denies RAM resource sharing actions when external
       principals are allowed:
       - ram:CreateResourceShare
       - ram:UpdateResourceShare
    2. The SCP has a condition that checks for external principals:
       {
           "Bool": {
               "ram:RequestedAllowsExternalPrincipals": "true"
           }
       }
    3. The SCP is attached to either the root OU or all top-level OUs
    4. The SCP has Resource = "*"

    Returns:
        A dictionary containing the finding for the SCP prevents RAM external
        sharing check.
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
                    "RAM external sharing cannot be assessed."
                ),
            },
        }

    # Check root OU for RAM external sharing deny SCP
    root_scps = org.root.scps
    root_has_ram_deny = False
    root_ram_deny_scp = None

    for scp in root_scps:
        try:
            content = json.loads(scp.content)
            if _is_ram_external_sharing_deny_scp(content):
                root_has_ram_deny = True
                root_ram_deny_scp = scp
                break
        except json.JSONDecodeError:
            continue

    # If root has RAM external sharing deny SCP, we're good
    if root_has_ram_deny:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "SCP preventing RAM external sharing is attached to the root OU."
                ),
                "scp": {
                    "id": root_ram_deny_scp.id,
                    "name": root_ram_deny_scp.name,
                    "arn": root_ram_deny_scp.arn,
                },
            },
        }

    # Check top-level OUs for RAM external sharing deny SCP
    top_level_ous = org.root.child_ous
    ous_without_ram_deny = []
    ous_with_ram_deny = []

    # If there's no RAM external sharing deny SCP on root and no top-level OUs,
    # that's a fail
    if not top_level_ous:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "SCP preventing RAM external sharing is not attached to the "
                    "root OU and there are no top-level OUs."
                ),
            },
        }

    for ou in top_level_ous:
        ou_has_ram_deny = False
        for scp in ou.scps:
            try:
                content = json.loads(scp.content)
                if _is_ram_external_sharing_deny_scp(content):
                    ou_has_ram_deny = True
                    ous_with_ram_deny.append(
                        {
                            "ou_name": ou.name,
                            "scp": {
                                "id": scp.id,
                                "name": scp.name,
                                "arn": scp.arn,
                            },
                        }
                    )
                    break
            except json.JSONDecodeError:
                continue

        if not ou_has_ram_deny:
            ous_without_ram_deny.append(ou.name)

    if ous_without_ram_deny:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "SCP preventing RAM external sharing is not attached to the "
                    "root OU or all top-level OUs. The following top-level OUs "
                    "do not have a RAM external sharing deny SCP: "
                )
                + ", ".join(ous_without_ram_deny),
            },
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS",
        "details": {
            "message": (
                "SCP preventing RAM external sharing is attached to all top-level OUs."
            ),
            "scps_by_ou": ous_with_ram_deny,
        },
    }


def _is_ram_external_sharing_deny_scp(content: dict[str, Any]) -> bool:
    """
    Check if an SCP effectively denies RAM external sharing.

    Args:
        content: The SCP content as a dictionary

    Returns:
        True if the SCP denies RAM external sharing with the required condition
    """
    if not isinstance(content, dict) or "Statement" not in content:
        return False

    statements = content["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    required_actions = {
        "ram:CreateResourceShare",
        "ram:UpdateResourceShare",
    }

    required_condition = {
        "Bool": {
            "ram:RequestedAllowsExternalPrincipals": "true",
        },
    }

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        # Check for a deny statement with the required RAM actions and condition
        if (
            statement.get("Effect") == "Deny"
            and "Action" in statement
            and "Resource" in statement
            and statement["Resource"] == "*"
            and "Condition" in statement
            and statement["Condition"] == required_condition
        ):
            actions = statement["Action"]
            if not isinstance(actions, list):
                actions = [actions]

            # Check if all required actions are present
            if all(action in actions for action in required_actions):
                return True

    return False


# Attach the check ID and name to the function
check_scp_prevents_ram_external_sharing._CHECK_ID = CHECK_ID
check_scp_prevents_ram_external_sharing._CHECK_NAME = CHECK_NAME
