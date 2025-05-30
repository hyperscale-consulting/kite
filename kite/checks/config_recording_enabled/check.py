"""Check for AWS Config recorders."""

from typing import Dict, Any

from kite.data import get_config_recorders
from kite.helpers import get_account_ids_in_scope
from kite.config import Config


CHECK_ID = "config-recording-enabled"
CHECK_NAME = "AWS Config Recording Enabled"


def check_config_recording_enabled() -> Dict[str, Any]:
    """
    Check if AWS Config recorders are enabled in all active regions.

    This check:
    1. Checks each active region in each in-scope account
    2. Verifies that Config recorders are present and enabled
    3. Records details about the recorders found

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - recorders_found: List of recorders found
                - missing_recorders: List of missing recorders
    """
    config = Config.get()
    missing_recorders = []
    recorders_found = []

    # Get all in-scope accounts
    accounts = get_account_ids_in_scope()

    # Check each account in each active region
    for account in accounts:
        for region in config.active_regions:
            recorders = get_config_recorders(account, region)
            if recorders:
                recorders_found.extend(recorders)
            else:
                missing_recorders.append(dict(account=account, region=region))

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS" if not missing_recorders else "FAIL",
        "details": {
            "missing_recorders": missing_recorders,
            "recorders_found": recorders_found,
        },
    }


# Attach the check ID and name to the function
check_config_recording_enabled._CHECK_ID = CHECK_ID
check_config_recording_enabled._CHECK_NAME = CHECK_NAME
