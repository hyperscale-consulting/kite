"""Check for VPC endpoint policies enforcing data perimeter controls."""

import json
from typing import Any

from kite.conditions import has_principal_org_id_condition
from kite.conditions import has_resource_org_id_condition
from kite.config import Config
from kite.data import get_organization
from kite.data import get_vpc_endpoints
from kite.helpers import get_account_ids_in_scope

CHECK_ID = "vpc-endpoints-enforce-data-perimeter"
CHECK_NAME = "VPC Endpoints Enforce Data Perimeter Controls"


def _has_required_org_conditions(policy_doc: dict[str, Any], org_id: str) -> bool:
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

        if has_principal_org_id_condition(
            conditions, org_id
        ) and has_resource_org_id_condition(conditions, org_id):
            return True

    return False


def check_vpc_endpoints_enforce_data_perimeter() -> dict[str, Any]:
    """
    Check if all VPC endpoints have the required endpoint policies for data
    perimeter controls.

    This check verifies that all VPC endpoints in all regions have endpoint
    policies that:
    1. Allow access when both the principal and resource are in the same
       organization

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
            "details": {"message": "AWS Organizations is not being used"},
        }

    # Get organization ID from the Organization model
    org_id = org.id

    # Get all in-scope accounts
    accounts = get_account_ids_in_scope()

    config = Config.get()
    failing_endpoints: list[dict[str, str]] = []
    for account in accounts:
        # Get VPC endpoints for each account in each region
        for region in config.active_regions:
            vpc_endpoints = get_vpc_endpoints(account, region)
            if not vpc_endpoints:
                continue

            for endpoint in vpc_endpoints:
                if "PolicyDocument" not in endpoint:
                    failing_endpoints.append(
                        {
                            "id": endpoint["VpcEndpointId"],
                            "account": account,
                            "region": region,
                            "reason": "No endpoint policy found",
                        }
                    )
                    continue

                try:
                    policy_doc = json.loads(endpoint["PolicyDocument"])
                except json.JSONDecodeError:
                    failing_endpoints.append(
                        {
                            "id": endpoint["VpcEndpointId"],
                            "account": account,
                            "region": region,
                            "reason": "Invalid policy document",
                        }
                    )
                    continue

                has_org_conditions = _has_required_org_conditions(policy_doc, org_id)

                if not has_org_conditions:
                    failing_endpoints.append(
                        {
                            "id": endpoint["VpcEndpointId"],
                            "account": account,
                            "region": region,
                            "reason": "Missing required organization conditions",
                        }
                    )

    if not failing_endpoints:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": "All VPC endpoints have the required endpoint policies"
            },
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": ("Some VPC endpoints are missing required endpoint policies"),
            "failing_resources": failing_endpoints,
        },
    }


# Attach the check ID and name to the function
check_vpc_endpoints_enforce_data_perimeter._CHECK_ID = CHECK_ID
check_vpc_endpoints_enforce_data_perimeter._CHECK_NAME = CHECK_NAME
