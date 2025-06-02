"""Check for AWS Detective coverage across the organization."""

from typing import Dict, Any, Set
from collections import defaultdict

from kite.data import get_organization, get_delegated_admins, get_detective_graphs
from kite.config import Config
from kite.helpers import get_account_ids_in_scope


CHECK_ID = "detective-enabled"
CHECK_NAME = "AWS Detective Enabled"


def _get_detective_delegated_admin(org) -> str:
    """
    Get the delegated administrator account for AWS Detective.

    Args:
        org: The organization object

    Returns:
        str: The account ID of the delegated administrator, or the management account ID
        if not found
    """
    detective_principal = "detective.amazonaws.com"
    delegated_admins = get_delegated_admins()

    if delegated_admins:
        for admin in delegated_admins:
            if admin.service_principal == detective_principal:
                return admin.id

    # If no delegated admin found, use the management account
    return org.master_account_id


def _check_detective_membership(
    account_ids: Set[str], region: str, admin_account: str
) -> tuple[Dict[str, list], Dict[str, list]]:
    """
    Check Detective membership for a set of accounts in a region.

    Args:
        account_ids: Set of account IDs to check
        region: The region to check
        admin_account: The account ID of the Detective administrator

    Returns:
        Tuple of (missing_accounts, disabled_accounts) dictionaries
    """
    missing_accounts = []
    disabled_accounts = []

    # Get Detective graphs from data module
    graphs = get_detective_graphs(admin_account, region)
    if not graphs:
        # If no graphs exist, all accounts are considered missing
        return list(account_ids), []

    # Get members from all graphs
    members = {}
    for graph in graphs:
        for member in graph.get("Members", []):
            members[member["AccountId"]] = member["Status"]

    # Check for missing accounts
    for account_id in account_ids:
        if account_id not in members:
            missing_accounts.append(account_id)
        elif members[account_id] != "ENABLED":
            disabled_accounts.append(account_id)

    return missing_accounts, disabled_accounts


def check_detective_enabled() -> Dict[str, Any]:
    """
    Check if AWS Detective is enabled for all organization accounts.

    This check:
    1. Verifies if an organization exists
    2. If organization exists:
       - Finds the delegated administrator for Detective
       - Checks that all organization accounts are members
    3. If no organization:
       - Checks each in-scope account's Detective graphs
       - Verifies that all in-scope accounts are members of at least one graph
    4. Verifies that each member account has status "ENABLED"

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
                - missing_accounts: Dict mapping regions to lists of missing account IDs
                - disabled_accounts: Dict mapping regions to lists of disabled account IDs
    """
    # Get all in-scope accounts
    account_ids = get_account_ids_in_scope()

    # Check if organization exists
    org = get_organization()
    if not org:
        # No organization - check each account's graphs
        missing_accounts = defaultdict(list)
        disabled_accounts = defaultdict(list)

        for region in Config.get().active_regions:
            # Check each account's graphs
            for account_id in account_ids:
                region_missing, region_disabled = _check_detective_membership(
                    account_ids, region, account_id
                )
                if region_missing:
                    missing_accounts[region].extend(region_missing)
                if region_disabled:
                    disabled_accounts[region].extend(region_disabled)

        # If any accounts are missing or disabled, the check fails
        if missing_accounts or disabled_accounts:
            message = "AWS Detective is not enabled for all in-scope accounts."
            if missing_accounts:
                message += "\n\nMissing accounts:"
                for region, accounts in missing_accounts.items():
                    message += f"\n{region}: {', '.join(accounts)}"
            if disabled_accounts:
                message += "\n\nDisabled accounts:"
                for region, accounts in disabled_accounts.items():
                    message += f"\n{region}: {', '.join(accounts)}"

            return {
                "check_id": CHECK_ID,
                "check_name": CHECK_NAME,
                "status": "FAIL",
                "details": {
                    "message": message,
                    "missing_accounts": dict(missing_accounts),
                    "disabled_accounts": dict(disabled_accounts),
                },
            }

        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": "AWS Detective is enabled for all in-scope accounts.",
            },
        }

    # Organization exists - use delegated admin
    delegated_admin = _get_detective_delegated_admin(org)
    missing_accounts = defaultdict(list)
    disabled_accounts = defaultdict(list)

    for region in Config.get().active_regions:
        region_missing, region_disabled = _check_detective_membership(
            account_ids, region, delegated_admin
        )
        if region_missing:
            missing_accounts[region].extend(region_missing)
        if region_disabled:
            disabled_accounts[region].extend(region_disabled)

    # If any accounts are missing or disabled, the check fails
    if missing_accounts or disabled_accounts:
        message = "AWS Detective is not enabled for all organization accounts."
        if missing_accounts:
            message += "\n\nMissing accounts:"
            for region, accounts in missing_accounts.items():
                message += f"\n{region}: {', '.join(accounts)}"
        if disabled_accounts:
            message += "\n\nDisabled accounts:"
            for region, accounts in disabled_accounts.items():
                message += f"\n{region}: {', '.join(accounts)}"

        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": message,
                "missing_accounts": dict(missing_accounts),
                "disabled_accounts": dict(disabled_accounts),
            },
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS",
        "details": {
            "message": "AWS Detective is enabled for all organization accounts.",
        },
    }


check_detective_enabled._CHECK_ID = CHECK_ID
check_detective_enabled._CHECK_NAME = CHECK_NAME
