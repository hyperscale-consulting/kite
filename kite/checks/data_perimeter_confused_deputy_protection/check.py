"""Check for data perimeter confused deputy protection."""

import json
from typing import Dict

from kite.data import get_organization
from kite.models import ControlPolicy
from kite.utils.aws_context_keys import (
    has_not_source_org_id_condition,
    has_no_source_account_condition,
    has_principal_is_aws_service_condition,
)


CHECK_ID = "data-perimeter-confused-deputy-protection"
CHECK_NAME = "Data Perimeter Confused Deputy Protection"


def _has_data_perimeter_confused_deputy_protection(
    policy: ControlPolicy, org_id: str
) -> bool:
    """
    Check if a policy has the required data perimeter confused deputy protection.

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
        # Check if this is a Deny statement with the required actions
        effect = statement.get("Effect")
        actions = statement.get("Action", [])
        principal = statement.get("Principal")
        resource = statement.get("Resource")

        required_actions = {
            "s3:*",
            "sqs:*",
            "kms:*",
            "secretsmanager:*",
            "sts:*"
        }

        if (
            effect != "Deny"
            or not all(action in actions for action in required_actions)
            or principal != "*"
            or resource != "*"
        ):
            continue

        # Check for required conditions
        conditions = statement.get("Condition", {})
        if not isinstance(conditions, dict):
            continue

        # Check for required conditions using case-insensitive functions
        if not has_not_source_org_id_condition(conditions, org_id):
            continue

        if not has_no_source_account_condition(conditions):
            continue

        if not has_principal_is_aws_service_condition(conditions):
            continue

        return True

    return False


def check_data_perimeter_confused_deputy_protection() -> Dict:
    """
    Check if there is data perimeter confused deputy protection in place.

    This check verifies that either the root OU or all top-level OUs have a Resource
    Control Policy (RCP) that prevents service-based access to data services unless it
    comes from within the AWS organization.

    Returns:
        A dictionary containing the check result
    """
    # Get organization data
    org = get_organization()
    if not org:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": "AWS Organizations is not being used"
            }
        }

    # Get organization ID from the Organization model
    org_id = org.id

    # Check if root OU has the required RCP
    root_has_protection = any(
        _has_data_perimeter_confused_deputy_protection(rcp, org_id)
        for rcp in org.root.rcps
    )

    if root_has_protection:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "Data perimeter confused deputy protection is attached to the "
                    "root OU"
                )
            }
        }

    # Check if all top-level OUs have the required RCP
    if not org.root.child_ous:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "Data perimeter confused deputy protection is not attached to the "
                    "root OU and there are no top-level OUs"
                )
            }
        }

    missing_ous = []
    for ou in org.root.child_ous:
        has_protection = any(
            _has_data_perimeter_confused_deputy_protection(rcp, org_id)
            for rcp in ou.rcps
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
                    "Data perimeter confused deputy protection is attached to all "
                    "top-level OUs"
                )
            }
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": (
                "Data perimeter confused deputy protection is not attached to the root "
                "OU or all top-level OUs. Missing protection in OUs: "
                f"{', '.join(missing_ous)}"
            )
        }
    }


check_data_perimeter_confused_deputy_protection._CHECK_ID = CHECK_ID
check_data_perimeter_confused_deputy_protection._CHECK_NAME = CHECK_NAME
