"""SCP prevents GuardDuty changes check module."""

import json
from typing import Any

from kite.data import get_organization

CHECK_ID = "scp-prevents-guardduty-changes"
CHECK_NAME = "SCP Prevents GuardDuty Changes"


def check_scp_prevents_guardduty_changes() -> dict:
    """
    Check if there is an effective SCP that prevents changes to GuardDuty.

    This check verifies that:
    1. There is an SCP that denies all GuardDuty management actions:
       - guardduty:AcceptInvitation
       - guardduty:ArchiveFindings
       - guardduty:CreateDetector
       - guardduty:CreateFilter
       - guardduty:CreateIPSet
       - guardduty:CreateMembers
       - guardduty:CreatePublishingDestination
       - guardduty:CreateSampleFindings
       - guardduty:CreateThreatIntelSet
       - guardduty:DeclineInvitations
       - guardduty:DeleteDetector
       - guardduty:DeleteFilter
       - guardduty:DeleteInvitations
       - guardduty:DeleteIPSet
       - guardduty:DeleteMembers
       - guardduty:DeletePublishingDestination
       - guardduty:DeleteThreatIntelSet
       - guardduty:DisassociateFromMasterAccount
       - guardduty:DisassociateMembers
       - guardduty:InviteMembers
       - guardduty:StartMonitoringMembers
       - guardduty:StopMonitoringMembers
       - guardduty:TagResource
       - guardduty:UnarchiveFindings
       - guardduty:UntagResource
       - guardduty:UpdateDetector
       - guardduty:UpdateFilter
       - guardduty:UpdateFindingsFeedback
       - guardduty:UpdateIPSet
       - guardduty:UpdatePublishingDestination
       - guardduty:UpdateThreatIntelSet
    2. The SCP is attached to either the root OU or all top-level OUs
    3. The SCP has Resource = "*"

    Returns:
        A dictionary containing the finding for the SCP prevents GuardDuty changes
        check.
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
                    "GuardDuty changes cannot be assessed."
                ),
            },
        }

    # Check root OU for GuardDuty deny SCP
    root_scps = org.root.scps
    root_has_guardduty_deny = False
    root_guardduty_deny_scp = None

    for scp in root_scps:
        try:
            content = json.loads(scp.content)
            if _is_guardduty_deny_scp(content):
                root_has_guardduty_deny = True
                root_guardduty_deny_scp = scp
                break
        except json.JSONDecodeError:
            continue

    # If root has GuardDuty deny SCP, we're good
    if root_has_guardduty_deny:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "SCP preventing GuardDuty changes is attached to the root OU."
                ),
                "scp": {
                    "id": root_guardduty_deny_scp.id,
                    "name": root_guardduty_deny_scp.name,
                    "arn": root_guardduty_deny_scp.arn,
                },
            },
        }

    # Check top-level OUs for GuardDuty deny SCP
    top_level_ous = org.root.child_ous
    ous_without_guardduty_deny = []
    ous_with_guardduty_deny = []

    # If there's no GuardDuty deny SCP on root and no top-level OUs, that's a fail
    if not top_level_ous:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "SCP preventing GuardDuty changes is not attached to the "
                    "root OU and there are no top-level OUs."
                ),
            },
        }

    for ou in top_level_ous:
        ou_has_guardduty_deny = False
        for scp in ou.scps:
            try:
                content = json.loads(scp.content)
                if _is_guardduty_deny_scp(content):
                    ou_has_guardduty_deny = True
                    ous_with_guardduty_deny.append(
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

        if not ou_has_guardduty_deny:
            ous_without_guardduty_deny.append(ou.name)

    if ous_without_guardduty_deny:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "SCP preventing GuardDuty changes is not attached to the "
                    "root OU or all top-level OUs. The following top-level OUs "
                    "do not have a GuardDuty deny SCP: "
                )
                + ", ".join(ous_without_guardduty_deny),
            },
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS",
        "details": {
            "message": (
                "SCP preventing GuardDuty changes is attached to all top-level OUs."
            ),
            "scps_by_ou": ous_with_guardduty_deny,
        },
    }


def _is_guardduty_deny_scp(content: dict[str, Any]) -> bool:
    """
    Check if an SCP effectively denies GuardDuty changes.

    Args:
        content: The SCP content as a dictionary

    Returns:
        True if the SCP denies all required GuardDuty actions
    """
    if not isinstance(content, dict) or "Statement" not in content:
        return False

    statements = content["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    required_actions = {
        "guardduty:AcceptInvitation",
        "guardduty:ArchiveFindings",
        "guardduty:CreateDetector",
        "guardduty:CreateFilter",
        "guardduty:CreateIPSet",
        "guardduty:CreateMembers",
        "guardduty:CreatePublishingDestination",
        "guardduty:CreateSampleFindings",
        "guardduty:CreateThreatIntelSet",
        "guardduty:DeclineInvitations",
        "guardduty:DeleteDetector",
        "guardduty:DeleteFilter",
        "guardduty:DeleteInvitations",
        "guardduty:DeleteIPSet",
        "guardduty:DeleteMembers",
        "guardduty:DeletePublishingDestination",
        "guardduty:DeleteThreatIntelSet",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:DisassociateMembers",
        "guardduty:InviteMembers",
        "guardduty:StartMonitoringMembers",
        "guardduty:StopMonitoringMembers",
        "guardduty:TagResource",
        "guardduty:UnarchiveFindings",
        "guardduty:UntagResource",
        "guardduty:UpdateDetector",
        "guardduty:UpdateFilter",
        "guardduty:UpdateFindingsFeedback",
        "guardduty:UpdateIPSet",
        "guardduty:UpdatePublishingDestination",
        "guardduty:UpdateThreatIntelSet",
    }

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        # Check for a deny statement with the required GuardDuty actions
        if (
            statement.get("Effect") == "Deny"
            and "Action" in statement
            and "Resource" in statement
            and statement["Resource"] == "*"
        ):
            actions = statement["Action"]
            if not isinstance(actions, list):
                actions = [actions]

            # Check if all required actions are present
            if all(action in actions for action in required_actions):
                return True

    return False


# Attach the check ID and name to the function
check_scp_prevents_guardduty_changes._CHECK_ID = CHECK_ID
check_scp_prevents_guardduty_changes._CHECK_NAME = CHECK_NAME
