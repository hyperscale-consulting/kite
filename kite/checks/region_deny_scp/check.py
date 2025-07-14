"""Region deny SCP check module."""

import json
from typing import Any

from kite.config import Config
from kite.data import get_organization

CHECK_ID = "region-deny-scp"
CHECK_NAME = "Region Deny SCP"


def check_region_deny_scp() -> dict:
    """
    Check if there is an effective region deny SCP in place.

    This check verifies that:
    1. There is an SCP that denies access to all regions except those in active_regions
    2. The SCP is attached to either the root OU or all top-level OUs

    Returns:
        A dictionary containing the finding for the Region Deny SCP check.
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
                        "AWS Organizations is not being used, so region deny SCP "
                        "cannot be assessed."
                    ),
                },
            }

        # Get the active regions from config
        active_regions = Config.get().active_regions
        if not active_regions:
            return {
                "check_id": CHECK_ID,
                "check_name": CHECK_NAME,
                "status": "FAIL",
                "details": {
                    "message": "No active regions configured.",
                },
            }

        # Check root OU for region deny SCP
        root_scps = org.root.scps
        root_has_region_deny = False
        root_region_deny_scp = None

        for scp in root_scps:
            try:
                content = json.loads(scp.content)
                if _is_region_deny_scp(content, active_regions):
                    root_has_region_deny = True
                    root_region_deny_scp = scp
                    break
            except json.JSONDecodeError:
                continue

        # If root has region deny SCP, we're good
        if root_has_region_deny:
            return {
                "check_id": CHECK_ID,
                "check_name": CHECK_NAME,
                "status": "PASS",
                "details": {
                    "message": (
                        "Region deny SCP is attached to the root OU. "
                        f"Allowed regions: {', '.join(active_regions)}"
                    ),
                    "scp": {
                        "id": root_region_deny_scp.id,
                        "name": root_region_deny_scp.name,
                        "arn": root_region_deny_scp.arn,
                    },
                },
            }

        # Check top-level OUs for region deny SCP
        top_level_ous = org.root.child_ous
        ous_without_region_deny = []

        # If there's no region deny SCP on root and no top-level OUs, that's a fail
        if not top_level_ous:
            return {
                "check_id": CHECK_ID,
                "check_name": CHECK_NAME,
                "status": "FAIL",
                "details": {
                    "message": (
                        "Region deny SCP is not attached to the root OU and "
                        "there are no top-level OUs."
                    ),
                },
            }

        for ou in top_level_ous:
            ou_has_region_deny = False
            for scp in ou.scps:
                try:
                    content = json.loads(scp.content)
                    if _is_region_deny_scp(content, active_regions):
                        ou_has_region_deny = True
                        break
                except json.JSONDecodeError:
                    continue

            if not ou_has_region_deny:
                ous_without_region_deny.append(ou.name)

        if ous_without_region_deny:
            return {
                "check_id": CHECK_ID,
                "check_name": CHECK_NAME,
                "status": "FAIL",
                "details": {
                    "message": (
                        "Region deny SCP is not attached to the root OU or all "
                        "top-level OUs. The following top-level OUs do not have a "
                        "region deny SCP: "
                    )
                    + ", ".join(ous_without_region_deny),
                },
            }

        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "Region deny SCP is attached to all top-level OUs. "
                    f"Allowed regions: {', '.join(active_regions)}"
                ),
            },
        }

    except Exception as e:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {"message": f"Error checking region deny SCP: {str(e)}"},
        }


def _is_region_deny_scp(content: dict[str, Any], allowed_regions: list[str]) -> bool:
    """
    Check if an SCP effectively denies access to all regions except the allowed ones.

    Args:
        content: The SCP content as a dictionary
        allowed_regions: List of regions that should be allowed

    Returns:
        True if the SCP denies access to all regions except the allowed ones
    """
    if not isinstance(content, dict) or "Statement" not in content:
        return False

    statements = content["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        # Check for a deny statement with region condition
        if (
            statement.get("Effect") == "Deny"
            and "Condition" in statement
            and "StringNotEquals" in statement["Condition"]
            and "aws:RequestedRegion" in statement["Condition"]["StringNotEquals"]
        ):
            denied_regions = statement["Condition"]["StringNotEquals"][
                "aws:RequestedRegion"
            ]
            if not isinstance(denied_regions, list):
                denied_regions = [denied_regions]

            # Check if all allowed regions are in the denied regions list
            if all(region in denied_regions for region in allowed_regions):
                return True

    return False


# Attach the check ID and name to the function
check_region_deny_scp._CHECK_ID = CHECK_ID
check_region_deny_scp._CHECK_NAME = CHECK_NAME
