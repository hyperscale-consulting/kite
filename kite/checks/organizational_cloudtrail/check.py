"""Check for organizational CloudTrail trail."""

from typing import Dict, Any

from kite.data import get_organization, get_cloudtrail_trails
from kite.helpers import get_account_ids_in_scope
from kite.config import Config


CHECK_ID = "organizational-cloudtrail"
CHECK_NAME = "Organizational CloudTrail"


def check_organizational_cloudtrail() -> Dict[str, Any]:
    """
    Check if there is an organizational CloudTrail trail.

    This check verifies that:
    1. AWS Organizations is being used
    2. There is at least one CloudTrail trail with IsOrganizationTrail=true

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    # Get organization data
    org = get_organization()
    if org is None:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "AWS Organizations is not being used, so organizational "
                    "CloudTrail cannot be assessed."
                ),
            },
        }

    # Get all in-scope accounts
    accounts = get_account_ids_in_scope()

    # Get active regions from config
    config = Config.get()
    active_regions = config.active_regions

    # Check each account in each active region for an organizational trail
    for account in accounts:
        for region in active_regions:
            trails = get_cloudtrail_trails(account, region)
            if not trails:
                continue

            for trail in trails:
                if trail.get("IsOrganizationTrail", False):
                    return {
                        "check_id": CHECK_ID,
                        "check_name": CHECK_NAME,
                        "status": "PASS",
                        "details": {
                            "message": (
                                "An organizational CloudTrail trail is configured."
                            ),
                            "trail": {
                                "name": trail["Name"],
                                "account": account,
                                "region": region,
                            },
                        },
                    }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": (
                "No organizational CloudTrail trail was found in any active region."
            ),
        },
    }


# Attach the check ID and name to the function
check_organizational_cloudtrail._CHECK_ID = CHECK_ID
check_organizational_cloudtrail._CHECK_NAME = CHECK_NAME
