"""Check for legacy CloudFront Origin Access Identities."""

from typing import Dict, Any, List

from kite.data import get_cloudfront_origin_access_identities
from kite.helpers import get_account_ids_in_scope


CHECK_ID = "migrate-from-oai"
CHECK_NAME = "Migrate from CloudFront Origin Access Identities"


def check_migrate_from_oai() -> Dict[str, Any]:
    """
    Check if any accounts are using legacy CloudFront Origin Access Identities.

    This check verifies that no accounts are using legacy CloudFront Origin Access
    Identities (OAIs) and have migrated to the newer Origin Access Control (OAC)
    mechanism.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - failing_resources: List of resources that failed the check
    """
    # Get in-scope accounts
    in_scope_accounts = get_account_ids_in_scope()

    # Track failing resources
    failing_resources: List[Dict[str, Any]] = []

    # Check each in-scope account for OAIs
    for account_id in in_scope_accounts:
        account_oais = get_cloudfront_origin_access_identities(account_id)
        if account_oais:
            failing_resources.append({
                "account_id": account_id,
                "resource_details": {
                    "oais": account_oais
                }
            })

    # Determine if the check passed
    passed = len(failing_resources) == 0

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS" if passed else "FAIL",
        "details": {
            "message": (
                "No accounts are using legacy CloudFront Origin Access Identities."
                if passed
                else (
                    f"Found {len(failing_resources)} accounts still using legacy "
                    "CloudFront Origin Access Identities."
                )
            ),
            "failing_resources": failing_resources,
        },
    }


# Attach the check ID and name to the function
check_migrate_from_oai._CHECK_ID = CHECK_ID
check_migrate_from_oai._CHECK_NAME = CHECK_NAME
