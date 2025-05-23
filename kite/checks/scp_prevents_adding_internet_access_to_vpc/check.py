"""SCP prevents adding internet access to VPC check module."""

import json
from typing import Dict, Any, List

from kite.data import get_organization


CHECK_ID = "scp-prevents-adding-internet-access-to-vpc"
CHECK_NAME = "SCP Prevents Adding Internet Access to VPC"


def check_scp_prevents_adding_internet_access_to_vpc() -> dict:
    """
    Check if there is an effective SCP that prevents adding internet access to VPCs.

    This check verifies that:
    1. There is an SCP that denies VPC internet access actions:
       - ec2:AttachInternetGateway
       - ec2:CreateInternetGateway
       - ec2:CreateEgressOnlyInternetGateway
       - ec2:CreateVpcPeeringConnection
       - ec2:AcceptVpcPeeringConnection
       - globalaccelerator:Create*
       - globalaccelerator:Update*
    2. The SCP has Resource = "*"
    3. The SCP is attached to any OU in the organization

    Returns:
        A dictionary containing the finding for the SCP prevents adding internet
        access to VPC check.
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
                    "adding internet access to VPC cannot be assessed."
                ),
            },
        }

    # Find all OUs with VPC internet access deny SCPs
    matching_scps = _find_matching_scps(org.root)

    if not matching_scps:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "No SCP preventing adding internet access to VPC was found "
                    "in any OU in the organization."
                ),
            },
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS",
        "details": {
            "message": (
                f"Found {len(matching_scps)} SCP(s) preventing adding internet "
                "access to VPC across the organization."
            ),
            "scps_by_ou": matching_scps,
        },
    }


def _find_matching_scps(ou) -> List[Dict[str, Any]]:
    """
    Recursively find all OUs with SCPs that prevent adding internet access to VPC.

    Args:
        ou: The OU to check and recursively check its children

    Returns:
        A list of dictionaries containing OU and SCP details
    """
    matching_scps = []

    # Check current OU's SCPs
    for scp in ou.scps:
        try:
            content = json.loads(scp.content)
            if _is_vpc_internet_access_deny_scp(content):
                matching_scps.append(
                    {
                        "ou_name": ou.name,
                        "scp": {
                            "id": scp.id,
                            "name": scp.name,
                            "arn": scp.arn,
                        },
                    }
                )
        except json.JSONDecodeError:
            continue

    # Recursively check child OUs
    for child_ou in ou.child_ous:
        matching_scps.extend(_find_matching_scps(child_ou))

    return matching_scps


def _is_vpc_internet_access_deny_scp(content: Dict[str, Any]) -> bool:
    """
    Check if an SCP effectively denies adding internet access to VPC.

    Args:
        content: The SCP content as a dictionary

    Returns:
        True if the SCP denies all required VPC internet access actions
    """
    if not isinstance(content, dict) or "Statement" not in content:
        return False

    statements = content["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    required_actions = {
        "ec2:AttachInternetGateway",
        "ec2:CreateInternetGateway",
        "ec2:CreateEgressOnlyInternetGateway",
        "ec2:CreateVpcPeeringConnection",
        "ec2:AcceptVpcPeeringConnection",
        "globalaccelerator:Create*",
        "globalaccelerator:Update*",
    }

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        # Check for a deny statement with the required VPC internet access actions
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
check_scp_prevents_adding_internet_access_to_vpc._CHECK_ID = CHECK_ID
check_scp_prevents_adding_internet_access_to_vpc._CHECK_NAME = CHECK_NAME
