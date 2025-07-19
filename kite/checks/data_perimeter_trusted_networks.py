"""Check for data perimeter trusted network controls in SCPs and RCPs."""

import json
from typing import Any

from kite.conditions import has_not_principal_arn_condition
from kite.conditions import has_not_source_ip_condition
from kite.conditions import has_not_source_vpc_condition
from kite.data import get_organization

CHECK_ID = "data-perimeter-trusted-networks"
CHECK_NAME = "Data Perimeter Enforces Trusted Networks"


def _has_required_conditions(policy_content: str) -> bool:
    """
    Check if a policy has at least one of the required trusted network conditions.

    Args:
        policy_content: The policy document to check

    Returns:
        True if the policy has at least one required condition, False otherwise
    """
    policy_doc = json.loads(policy_content)
    if "Statement" not in policy_doc:
        return False

    for statement in policy_doc["Statement"]:
        # Check if this is a Deny statement
        effect = statement.get("Effect")
        if effect != "Deny":
            continue

        # Check for required conditions
        conditions = statement.get("Condition", {})
        if not isinstance(conditions, dict):
            continue

        # Check for any of the required conditions using case-insensitive functions
        if has_not_source_ip_condition(conditions):
            return True

        if has_not_source_vpc_condition(conditions):
            return True

        if has_not_principal_arn_condition(conditions):
            return True

    return False


def check_data_perimeter_trusted_networks() -> dict[str, Any]:
    """
    Check if SCPs and RCPs have the required data perimeter trusted network
    controls.

    This check verifies that:
    1. There is at least one SCP at the root or top-level OUs with a Deny
       effect and at least one of:
       - NotIpAddressIfExists condition for aws:SourceIp
       - StringNotEqualsIfExists condition for aws:SourceVpc
       - ArnNotLikeIfExists condition for aws:PrincipalArn
    2. There is at least one RCP at the root or top-level OUs with a Deny
       effect and matching conditions

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or
              "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - failing_resources: List of resources that failed the check
    """
    # Get organization data
    org = get_organization()
    if not org:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {"message": "AWS Organizations is not being used"},
        }

    # Get root and top-level OUs
    root = org.root
    top_level_ous = root.child_ous

    # Check SCPs
    has_scp_controls = False
    failing_scps: list[dict[str, str]] = []

    # Check root SCPs
    root_scps = root.scps
    for scp in root_scps:
        if _has_required_conditions(scp.content):
            has_scp_controls = True
            break
        else:
            failing_scps.append(
                {
                    "id": scp.id,
                    "type": "SCP",
                    "target": "Root",
                    "reason": "Missing required trusted network conditions",
                }
            )

    # Check top-level OU SCPs
    if not has_scp_controls:
        for ou in top_level_ous:
            for scp in ou.scps:
                if _has_required_conditions(scp.content):
                    has_scp_controls = True
                    break
                else:
                    failing_scps.append(
                        {
                            "id": scp.id,
                            "type": "SCP",
                            "target": ou.name,
                            "reason": "Missing required trusted network conditions",
                        }
                    )
            if has_scp_controls:
                break

    # Check RCPs
    has_rcp_controls = False
    failing_rcps: list[dict[str, str]] = []

    # Check root RCPs
    root_rcps = root.rcps
    for rcp in root_rcps:
        if _has_required_conditions(rcp.content):
            has_rcp_controls = True
            break
        else:
            failing_rcps.append(
                {
                    "id": rcp.id,
                    "type": "RCP",
                    "target": "Root",
                    "reason": "Missing required trusted network conditions",
                }
            )

    # Check top-level OU RCPs
    if not has_rcp_controls:
        for ou in top_level_ous:
            for rcp in ou.rcps:
                if _has_required_conditions(rcp.content):
                    has_rcp_controls = True
                    break
                else:
                    failing_rcps.append(
                        {
                            "id": rcp.id,
                            "type": "RCP",
                            "target": ou.name,
                            "reason": "Missing required trusted network conditions",
                        }
                    )
            if has_rcp_controls:
                break

    if has_scp_controls and has_rcp_controls:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "Data perimeter trusted network controls are enforced by both "
                    "SCPs and RCPs"
                )
            },
        }

    failing_resources = failing_scps + failing_rcps
    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": (
                "Data perimeter trusted network controls are not enforced by both "
                "SCPs and RCPs"
            ),
            "failing_resources": failing_resources,
        },
    }


# Attach the check ID and name to the function
check_data_perimeter_trusted_networks._CHECK_ID = CHECK_ID
check_data_perimeter_trusted_networks._CHECK_NAME = CHECK_NAME
