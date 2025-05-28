"""Check for VPC flow logs being enabled."""

from typing import Dict, Any, List

from kite.data import get_vpcs, get_flow_logs
from kite.helpers import get_account_ids_in_scope
from kite.config import Config


CHECK_ID = "vpc-flow-logs-enabled"
CHECK_NAME = "VPC Flow Logs Enabled"


def check_vpc_flow_logs_enabled() -> Dict[str, Any]:
    """
    Check if all VPCs have flow logs enabled.

    This check verifies that:
    1. Each VPC in each account and region has at least one flow log enabled
    2. Flow logs are properly configured to capture traffic

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
                - failing_resources: List of VPCs that don't have flow logs enabled
    """
    config = Config.get()
    failing_vpcs: List[Dict[str, str]] = []

    # Get all in-scope accounts
    accounts = get_account_ids_in_scope()

    # Check each account in each active region
    for account in accounts:
        for region in config.active_regions:
            # Get VPCs and flow logs for this account and region
            vpcs = get_vpcs(account, region)
            flow_logs = get_flow_logs(account, region)

            # Create a set of VPC IDs that have flow logs enabled
            vpcs_with_flow_logs = {
                log["ResourceId"] for log in flow_logs
                if log.get("ResourceId") and log.get("FlowLogStatus") == "ACTIVE"
            }

            # Check each VPC
            for vpc in vpcs:
                vpc_id = vpc.get("VpcId")
                if not vpc_id:
                    continue

                if vpc_id not in vpcs_with_flow_logs:
                    failing_vpcs.append({
                        "id": vpc_id,
                        "account": account,
                        "region": region,
                        "name": vpc.get("Tags", {}).get("Name", "Unnamed VPC"),
                        "reason": "No active flow logs found"
                    })

    if not failing_vpcs:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": "All VPCs have flow logs enabled"
            }
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": (
                f"Found {len(failing_vpcs)} VPC(s) without flow logs enabled"
            ),
            "failing_resources": failing_vpcs
        }
    }


# Attach the check ID and name to the function
check_vpc_flow_logs_enabled._CHECK_ID = CHECK_ID
check_vpc_flow_logs_enabled._CHECK_NAME = CHECK_NAME
