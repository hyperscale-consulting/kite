"""Check for confused deputy protection for S3."""

import json
from typing import Dict

from kite.data import get_organization
from kite.models import ControlPolicy


CHECK_ID = "confused-deputy-protection-for-s3"
CHECK_NAME = "Confused Deputy Protection for S3"


def _has_confused_deputy_protection(policy: ControlPolicy, org_id: str) -> bool:
    """
    Check if a policy has the required confused deputy protection for S3.

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

        # Check if this is a Deny statement for S3 actions
        effect = statement.get("Effect")
        actions = statement.get("Action", [])
        principal = statement.get("Principal")
        resource = statement.get("Resource")

        if (
            effect != "Deny"
            or not any(action.startswith("s3:") for action in actions)
            or principal != "*"
            or resource != "*"
        ):
            continue

        # Check for required conditions
        conditions = statement.get("Condition", {})
        if not isinstance(conditions, dict):
            continue

        # Check for aws:SourceOrgID condition
        source_org = conditions.get("StringNotEqualsIfExists", {}).get("aws:SourceOrgID")
        if source_org != org_id:
            continue

        # Check for aws:SourceAccount condition
        source_account = conditions.get("Null", {}).get("aws:SourceAccount")
        if source_account != "false":
            continue

        # Check for aws:PrincipalIsAWSService condition
        principal_is_service = conditions.get("Bool", {}).get("aws:PrincipalIsAWSService")
        if principal_is_service != "true":
            continue

        return True

    return False


def check_confused_deputy_protection_for_s3() -> Dict:
    """
    Check if there is confused deputy protection for S3 in place.

    This check verifies that either the root OU or all top-level OUs have a Resource
    Control Policy (RCP) that prevents service-based access to S3 unless it comes from
    within the AWS organization.

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
        _has_confused_deputy_protection(rcp, org_id)
        for rcp in org.root.rcps
    )

    if root_has_protection:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": "Confused deputy protection for S3 is attached to the root OU"
            }
        }

    # Check if all top-level OUs have the required RCP
    if not org.root.child_ous:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": "Confused deputy protection for S3 is not attached to the root OU and there are no top-level OUs"
            }
        }

    missing_ous = []
    for ou in org.root.child_ous:
        has_protection = any(
            _has_confused_deputy_protection(rcp, org_id)
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
                "message": "Confused deputy protection for S3 is attached to all top-level OUs"
            }
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": (
                "Confused deputy protection for S3 is not attached to the root OU or all top-level OUs. "
                f"Missing protection in OUs: {', '.join(missing_ous)}"
            )
        }
    }


check_confused_deputy_protection_for_s3._CHECK_ID = CHECK_ID
check_confused_deputy_protection_for_s3._CHECK_NAME = CHECK_NAME
