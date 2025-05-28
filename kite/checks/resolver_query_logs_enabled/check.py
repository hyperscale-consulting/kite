"""Check for Route 53 Resolver query logs being enabled."""

from typing import Dict, Any, List

from kite.data import get_vpcs, get_route53resolver_resolver_query_log_config_associations
from kite.helpers import get_account_ids_in_scope
from kite.config import Config


CHECK_ID = "resolver-query-logs-enabled"
CHECK_NAME = "Route 53 Resolver Query Logs Enabled"


def check_resolver_query_logs_enabled() -> Dict[str, Any]:
    """
    Check if all VPCs have Route 53 Resolver query logs enabled.

    This check verifies that:
    1. Each VPC in each account and region has at least one resolver query log config association
    2. The resolver query log config associations are properly configured

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
                - failing_resources: List of VPCs that don't have query logs enabled
    """
    config = Config.get()
    failing_vpcs: List[Dict[str, str]] = []

    # Get all in-scope accounts
    accounts = get_account_ids_in_scope()

    # Check each account in each active region
    for account in accounts:
        for region in config.active_regions:
            # Get VPCs and resolver query log config associations for this account and region
            vpcs = get_vpcs(account, region)
            query_log_associations = get_route53resolver_resolver_query_log_config_associations(account, region)

            # Create a set of VPC IDs that have query logs enabled
            vpcs_with_query_logs = {
                assoc["ResourceId"] for assoc in query_log_associations
                if assoc.get("ResourceId") and assoc.get("Status") == "ACTIVE"
            }

            # Check each VPC
            for vpc in vpcs:
                vpc_id = vpc.get("VpcId")
                if not vpc_id:
                    continue

                if vpc_id not in vpcs_with_query_logs:
                    failing_vpcs.append({
                        "id": vpc_id,
                        "account": account,
                        "region": region,
                        "reason": "No active resolver query log config association found"
                    })

    if not failing_vpcs:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": "All VPCs have Route 53 Resolver query logs enabled"
            }
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": (
                f"Found {len(failing_vpcs)} VPC(s) without Route 53 Resolver query logs enabled"
            ),
            "failing_resources": failing_vpcs
        }
    }


# Attach the check ID and name to the function
check_resolver_query_logs_enabled._CHECK_ID = CHECK_ID
check_resolver_query_logs_enabled._CHECK_NAME = CHECK_NAME
