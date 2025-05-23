"""SCP prevents CloudWatch changes check module."""

import json
from typing import Dict, Any, List, Tuple

from kite.data import get_organization


CHECK_ID = "scp-prevents-cloudwatch-changes"
CHECK_NAME = "SCP Prevents CloudWatch Changes"


def check_scp_prevents_cloudwatch_changes() -> dict:
    """
    Check if there is an SCP that prevents changes to CloudWatch configuration.

    This check verifies that there is at least one SCP that denies the following
    CloudWatch actions:
    - cloudwatch:DeleteAlarms
    - cloudwatch:DeleteDashboards
    - cloudwatch:DisableAlarmActions
    - cloudwatch:PutDashboard
    - cloudwatch:PutMetricAlarm
    - cloudwatch:SetAlarmState

    The SCP must have:
    1. Effect = Deny
    2. Resource = "*"
    3. All the specified CloudWatch actions

    Returns:
        A dictionary containing the finding for the SCP prevents CloudWatch changes
        check, including details of all matching SCPs and their OUs.
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
                    "CloudWatch changes cannot be assessed."
                ),
            },
        }

    # Check all OUs for CloudWatch deny SCPs
    def check_ou_for_cloudwatch_deny(ou) -> List[Tuple[str, Dict[str, str]]]:
        matching_scps = []
        for scp in ou.scps:
            try:
                content = json.loads(scp.content)
                if _is_cloudwatch_deny_scp(content):
                    matching_scps.append(
                        (
                            ou.name,
                            {
                                "id": scp.id,
                                "name": scp.name,
                                "arn": scp.arn,
                            },
                        )
                    )
            except json.JSONDecodeError:
                continue
        return matching_scps

    # Check all OUs recursively
    def check_ous_recursively(ou) -> List[Tuple[str, Dict[str, str]]]:
        matching_scps = []

        # Check current OU
        matching_scps.extend(check_ou_for_cloudwatch_deny(ou))

        # Check child OUs
        for child_ou in ou.child_ous:
            matching_scps.extend(check_ous_recursively(child_ou))

        return matching_scps

    # Start checking from root
    matching_scps = check_ous_recursively(org.root)

    if matching_scps:
        # Group SCPs by OU for better readability
        scps_by_ou = {}
        for ou_name, scp_details in matching_scps:
            if ou_name not in scps_by_ou:
                scps_by_ou[ou_name] = []
            scps_by_ou[ou_name].append(scp_details)

        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "Found SCPs preventing CloudWatch changes in the following "
                    "OUs: "
                )
                + ", ".join(scps_by_ou.keys()),
                "scps_by_ou": scps_by_ou,
            },
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": (
                "No SCP preventing CloudWatch changes was found in any OU in "
                "the organization."
            ),
        },
    }


def _is_cloudwatch_deny_scp(content: Dict[str, Any]) -> bool:
    """
    Check if an SCP effectively denies CloudWatch changes.

    Args:
        content: The SCP content as a dictionary

    Returns:
        True if the SCP denies the required CloudWatch actions
    """
    if not isinstance(content, dict) or "Statement" not in content:
        return False

    statements = content["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    required_actions = {
        "cloudwatch:DeleteAlarms",
        "cloudwatch:DeleteDashboards",
        "cloudwatch:DisableAlarmActions",
        "cloudwatch:PutDashboard",
        "cloudwatch:PutMetricAlarm",
        "cloudwatch:SetAlarmState",
    }

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        # Check for a deny statement with the required CloudWatch actions
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
check_scp_prevents_cloudwatch_changes._CHECK_ID = CHECK_ID
check_scp_prevents_cloudwatch_changes._CHECK_NAME = CHECK_NAME
