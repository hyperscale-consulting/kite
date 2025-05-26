"""Check for data perimeter trusted identities RCP."""

import json
from typing import Dict, Any

from kite.data import get_organization
from kite.models import ControlPolicy


CHECK_ID = "data-perimeter-trusted-identities"
CHECK_NAME = "Data Perimeter Enforces Trusted Identities"


def _has_data_perimeter_trusted_identities(policy: ControlPolicy, org_id: str) -> bool:
    """
    Check if a policy has the required data perimeter trusted identities protection.

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
            "sts:AssumeRole",
            "sts:DecodeAuthorizationMessage",
            "sts:GetAccessKeyInfo",
            "sts:GetFederationToken",
            "sts:GetServiceBearerToken",
            "sts:GetSessionToken",
            "sts:SetContext"
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

        # Check for aws:PrincipalOrgID condition
        org_condition = (
            conditions.get("StringNotEqualsIfExists", {})
            .get("aws:PrincipalOrgID")
        )
        if org_condition != org_id:
            continue

        # Check for aws:PrincipalIsAWSService condition
        service_condition = (
            conditions.get("BoolIfExists", {})
            .get("aws:PrincipalIsAWSService")
        )
        if service_condition != "false":
            continue

        return True

    return False


def check_establish_data_perimeter_trusted_identities() -> Dict[str, Any]:
    """
    Check if there is a data perimeter trusted identities RCP in place.

    This check verifies that either the root OU or all top-level OUs have a Resource
    Control Policy (RCP) that enforces organization identities for data perimeter
    controls by denying access to sensitive services unless the request comes from
    within the AWS organization.

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
            "details": {
                "message": "AWS Organizations is not being used"
            }
        }

    # Get organization ID from the Organization model
    org_id = org.id

    # Check if root OU has the required RCP
    root_has_protection = any(
        _has_data_perimeter_trusted_identities(rcp, org_id)
        for rcp in org.root.rcps
    )

    if root_has_protection:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "Data perimeter trusted identities RCP is attached to the root OU"
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
                    "Data perimeter trusted identities RCP is not attached to the root OU "
                    "and there are no top-level OUs"
                )
            }
        }

    missing_ous = []
    for ou in org.root.child_ous:
        has_protection = any(
            _has_data_perimeter_trusted_identities(rcp, org_id)
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
                    "Data perimeter trusted identities RCP is attached to all top-level OUs"
                )
            }
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": (
                "Data perimeter trusted identities RCP is not attached to the root OU or "
                f"all top-level OUs. Missing protection in OUs: {', '.join(missing_ous)}"
            )
        }
    }


# Attach the check ID and name to the function
check_establish_data_perimeter_trusted_identities._CHECK_ID = CHECK_ID
check_establish_data_perimeter_trusted_identities._CHECK_NAME = CHECK_NAME
