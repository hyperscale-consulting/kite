"""Check for ELB logging configuration."""

from typing import Any

from kite.config import Config
from kite.data import get_elbv2_load_balancers
from kite.helpers import get_account_ids_in_scope

CHECK_ID = "elb-logging-enabled"
CHECK_NAME = "ELB Logging Enabled"


def check_elb_logging_enabled() -> dict[str, Any]:
    """
    Check if logging is enabled for all ELBs.

    This check:
    1. Gets all ELBs in each account and region
    2. Verifies that each ELB has access logs enabled
    3. Fails if any ELBs are found without logging enabled

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    config = Config.get()
    elbs_without_logging = []
    elbs_with_logging = []

    # Get all in-scope accounts
    accounts = get_account_ids_in_scope()

    # Check each account in each active region
    for account in accounts:
        for region in config.active_regions:
            # Get ELBs for this account and region
            elbs = get_elbv2_load_balancers(account, region)

            # Check each ELB
            for elb in elbs:
                elb_name = elb.get("LoadBalancerName", "Unknown")
                attributes = elb.get("Attributes", {})
                access_logs_enabled = attributes.get("access_logs.s3.enabled", "false")

                elb_info = f"ELB: {elb_name} (Account: {account}, Region: {region})"

                if access_logs_enabled.lower() == "true":
                    elbs_with_logging.append(elb_info)
                else:
                    elbs_without_logging.append(elb_info)

    # Build the message
    message = "This check verifies that logging is enabled for all ELBs.\n\n"

    if elbs_without_logging:
        message += (
            "The following ELBs do not have logging enabled:\n"
            + "\n".join(f"  - {elb}" for elb in sorted(elbs_without_logging))
            + "\n\n"
        )

    if elbs_with_logging:
        message += (
            "The following ELBs have logging enabled:\n"
            + "\n".join(f"  - {elb}" for elb in sorted(elbs_with_logging))
            + "\n\n"
        )

    if not elbs_without_logging and not elbs_with_logging:
        message += "No ELBs found in any account or region.\n\n"

    # Determine status based on whether any ELBs are missing logging
    if elbs_without_logging:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": message,
            },
        }
    else:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": message,
            },
        }


# Attach the check ID and name to the function
check_elb_logging_enabled._CHECK_ID = CHECK_ID
check_elb_logging_enabled._CHECK_NAME = CHECK_NAME
