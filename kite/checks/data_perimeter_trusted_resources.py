"""Check for data perimeter trusted resources SCP."""

import json
from typing import Any

from kite.conditions import has_not_resource_org_id_condition
from kite.data import get_organization
from kite.models import ControlPolicy

CHECK_ID = "data-perimeter-trusted-resources"
CHECK_NAME = "Data Perimeter Enforces Trusted Resources"


def _has_data_perimeter_trusted_resources(policy: ControlPolicy, org_id: str) -> bool:
    """
    Check if a policy has the required data perimeter trusted resources protection.

    Args:
        policy: The policy to check
        org_id: The organization ID to check against

    Returns:
        True if the policy has the required protection, False otherwise
    """
    try:
        policy_doc = json.loads(policy.content)
    except json.JSONDecodeError:
        return False

    if not isinstance(policy_doc, dict) or "Statement" not in policy_doc:
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

        # Check for aws:ResourceOrgID condition
        if has_not_resource_org_id_condition(conditions, org_id):
            return True

    return False


def check_data_perimeter_trusted_resources() -> dict[str, Any]:
    """
    Check if there is a data perimeter trusted resources SCP in place.

    This check verifies that either the root OU or all top-level OUs have a Service
    Control Policy (SCP) that enforces trusted resources protection for data perimeter
    controls by denying access to resources outside the AWS organization.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
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

    # Get organization ID from the Organization model
    org_id = org.id

    # Check if root OU has the required SCP
    root_has_protection = any(
        _has_data_perimeter_trusted_resources(scp, org_id) for scp in org.root.scps
    )

    if root_has_protection:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "Data perimeter trusted resources SCP is attached to the root OU"
                )
            },
        }

    # Check if all top-level OUs have the required SCP
    if not org.root.child_ous:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "Data perimeter trusted resources SCP is not attached to "
                    "the root OU and there are no top-level OUs"
                )
            },
        }

    missing_ous = []
    for ou in org.root.child_ous:
        has_protection = any(
            _has_data_perimeter_trusted_resources(scp, org_id) for scp in ou.scps
        )
        if not has_protection:
            missing_ous.append(ou.name)

    if not missing_ous:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "Data perimeter trusted resources SCP is attached to "
                    "all top-level OUs"
                )
            },
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": (
                "Data perimeter trusted resources SCP is not attached to "
                "the root OU or all top-level OUs. Missing protection in OUs: "
                f"{', '.join(missing_ous)}"
            )
        },
    }


# Attach the check ID and name to the function
check_data_perimeter_trusted_resources._CHECK_ID = CHECK_ID
check_data_perimeter_trusted_resources._CHECK_NAME = CHECK_NAME
