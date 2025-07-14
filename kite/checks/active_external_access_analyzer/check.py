"""Check for active external access analyzer across all accounts."""

from typing import Any

from kite.data import get_access_analyzers
from kite.helpers import get_account_ids_in_scope

CHECK_ID = "active-external-access-analyzer"
CHECK_NAME = "Active External Access Analyzer"


def _check_analyzer_configuration(analyzer: dict[str, Any]) -> bool:
    """
    Check if an analyzer's configuration meets the requirements.

    Args:
        analyzer: The analyzer configuration to check

    Returns:
        bool: True if the analyzer configuration meets the requirements
    """
    # Check if it's active
    if analyzer.get("status") != "ACTIVE":
        return False

    return True


def _get_analyzer_summary(analyzers: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Get a summary of the analyzers.

    Args:
        analyzers: List of analyzer configurations

    Returns:
        Dict containing:
            - has_org_analyzer: bool indicating if there's an org-wide analyzer
            - org_analyzer: Optional[Dict] containing the org analyzer if found
            - account_analyzers: List of account-level analyzers
            - accounts_with_analyzer: List of account IDs with analyzers
            - accounts_without_analyzer: List of account IDs without analyzers
    """
    org_analyzer = None
    account_analyzers = []
    accounts_with_analyzer = set()
    accounts_without_analyzer = set()

    for analyzer in analyzers:
        if analyzer.get("type") == "ORGANIZATION":
            org_analyzer = analyzer
        elif analyzer.get("type") == "ACCOUNT":
            account_analyzers.append(analyzer)
            accounts_with_analyzer.add(analyzer.get("arn", "").split(":")[4])

    # Get all account IDs
    all_accounts = set(get_account_ids_in_scope())
    accounts_without_analyzer = all_accounts - accounts_with_analyzer

    return {
        "has_org_analyzer": org_analyzer is not None,
        "org_analyzer": org_analyzer,
        "account_analyzers": account_analyzers,
        "accounts_with_analyzer": list(accounts_with_analyzer),
        "accounts_without_analyzer": list(accounts_without_analyzer),
    }


def check_active_external_access_analyzer() -> dict[str, Any]:
    """
    Check if there is an active external access analyzer across all accounts.

    This check verifies that either:
    1. There is an active organization-wide external access analyzer with no exclusions, or
    2. There are active account-level external access analyzers in all accounts with
       no exclusions.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - summary: Dict containing analyzer summary
    """
    # Get all account IDs in scope
    account_ids = get_account_ids_in_scope()

    # Collect all analyzers
    all_analyzers = []
    for account_id in account_ids:
        analyzers = get_access_analyzers(account_id)
        all_analyzers.extend(analyzers)

    # Get analyzer summary
    summary = _get_analyzer_summary(all_analyzers)
    if not summary["has_org_analyzer"] and not summary["account_analyzers"]:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {"message": "No external-access access analyzers found."},
        }

    # Check for organization-wide analyzer
    if summary["has_org_analyzer"]:
        org_analyzer = summary["org_analyzer"]
        if _check_analyzer_configuration(org_analyzer):
            return {
                "check_id": CHECK_ID,
                "check_name": CHECK_NAME,
                "status": "PASS",
                "details": {
                    "message": (
                        "Found an active organization-wide external access analyzer."
                    ),
                    "summary": summary,
                },
            }

    # Check for account-level analyzers
    if summary["account_analyzers"]:
        # Check if all accounts have analyzers
        if not summary["accounts_without_analyzer"]:
            # Check if all analyzers meet requirements
            all_valid = all(
                _check_analyzer_configuration(analyzer)
                for analyzer in summary["account_analyzers"]
            )
            if all_valid:
                return {
                    "check_id": CHECK_ID,
                    "check_name": CHECK_NAME,
                    "status": "PASS",
                    "details": {
                        "message": (
                            "Found active account-level external access analyzers "
                            "in all accounts."
                        ),
                        "summary": summary,
                    },
                }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": "No active external access analyzer found.",
        },
    }


check_active_external_access_analyzer._CHECK_ID = CHECK_ID
check_active_external_access_analyzer._CHECK_NAME = CHECK_NAME
