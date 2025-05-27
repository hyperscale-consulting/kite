"""Check for VPC endpoint policies enforcing data perimeter controls."""

import json
from typing import Dict, Any, List

from kite.data import get_organization, get_vpc_endpoints
from kite.helpers import get_account_ids_in_scope
from kite.config import Config


CHECK_ID = "vpc-endpoints-enforce-data-perimeter"
CHECK_NAME = "VPC Endpoints Enforce Data Perimeter Controls"


def _has_required_org_conditions(
    policy_doc: Dict[str, Any], org_id: str
) -> bool:
    """
    Check if a policy has the required organization conditions.

    Args:
        policy_doc: The policy document to check
        org_id: The organization ID to check against

    Returns:
        True if the policy has the required conditions, False otherwise
    """
    if not isinstance(policy_doc, dict) or "Statement" not in policy_doc:
        return False

    for statement in policy_doc["Statement"]:
        # Check if this is an Allow statement
        effect = statement.get("Effect")
        if effect != "Allow":
            continue

        # Check for required conditions
        conditions = statement.get("Condition", {})
        if not isinstance(conditions, dict):
            continue

        # Check for aws:PrincipalOrgID and aws:ResourceOrgID conditions
        string_equals = conditions.get("StringEquals", {})
        if not isinstance(string_equals, dict):
            continue

        principal_org = string_equals.get("aws:PrincipalOrgID")
        resource_org = string_equals.get("aws:ResourceOrgID")

        if principal_org != org_id or resource_org != org_id:
            continue

        return True

    return False


def _has_required_service_condition(
    policy_doc: Dict[str, Any]
) -> bool:
    """
    Check if a policy has the required AWS service condition.

    Args:
        policy_doc: The policy document to check

    Returns:
        True if the policy has the required condition, False otherwise
    """
    if not isinstance(policy_doc, dict) or "Statement" not in policy_doc:
        return False

    for statement in policy_doc["Statement"]:
        # Check if this is an Allow statement
        effect = statement.get("Effect")
        if effect != "Allow":
            continue

        # Check for required conditions
        conditions = statement.get("Condition", {})
        if not isinstance(conditions, dict):
            continue

        # Check for aws:PrincipalIsAWSService condition
        bool_condition = conditions.get("Bool", {})
        if not isinstance(bool_condition, dict):
            continue

        service_condition = bool_condition.get("aws:PrincipalIsAWSService")
        if service_condition != "true":
            continue

        return True

    return False


def check_vpc_endpoints_enforce_data_perimeter() -> Dict[str, Any]:
    """
    Check if all VPC endpoints have the required endpoint policies for data
    perimeter controls.

    This check verifies that all VPC endpoints in all regions have endpoint
    policies that:
    1. Allow access when both the principal and resource are in the same
       organization
    2. Allow access when the principal is an AWS service

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", or "FAIL")
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

    # Get all in-scope accounts
    accounts = get_account_ids_in_scope()

    config = Config.get()
    failing_endpoints: List[Dict[str, str]] = []
    for account in accounts:
        # Get VPC endpoints for each account in each region
        for region in config.active_regions:
            vpc_endpoints = get_vpc_endpoints(account, region)
            if not vpc_endpoints:
                continue

            for endpoint in vpc_endpoints:
                if 'PolicyDocument' not in endpoint:
                    failing_endpoints.append({
                        "id": endpoint['VpcEndpointId'],
                        "account": account,
                        "region": region,
                        "reason": "No endpoint policy found"
                    })
                    continue

                try:
                    policy_doc = json.loads(endpoint['PolicyDocument'])
                except json.JSONDecodeError:
                    failing_endpoints.append({
                        "id": endpoint['VpcEndpointId'],
                        "account": account,
                        "region": region,
                        "reason": "Invalid policy document"
                    })
                    continue

                has_org_conditions = _has_required_org_conditions(policy_doc, org_id)
                has_service_condition = _has_required_service_condition(policy_doc)

                if not has_org_conditions or not has_service_condition:
                    missing_conditions = []
                    if not has_org_conditions:
                        missing_conditions.append("organization conditions")
                    if not has_service_condition:
                        missing_conditions.append("AWS service condition")

                    failing_endpoints.append({
                        "id": endpoint['VpcEndpointId'],
                        "account": account,
                        "region": region,
                        "reason": (
                            "Missing required conditions: "
                            f"{' and '.join(missing_conditions)}"
                        )
                    })

    if not failing_endpoints:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": "All VPC endpoints have the required endpoint policies"
            }
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": (
                "Some VPC endpoints are missing required endpoint policies"
            ),
            "failing_resources": failing_endpoints
        }
    }


# Attach the check ID and name to the function
check_vpc_endpoints_enforce_data_perimeter._CHECK_ID = CHECK_ID
check_vpc_endpoints_enforce_data_perimeter._CHECK_NAME = CHECK_NAME
