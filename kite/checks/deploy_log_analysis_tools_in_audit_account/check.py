"""Check for log analysis tools deployment in audit account."""

from typing import Dict, Any, Optional

from kite.data import get_organization
from kite.helpers import manual_check


CHECK_ID = "deploy-log-analysis-tools-in-audit-account"
CHECK_NAME = "Deploy Log Analysis Tools in Audit Account"


def _find_audit_account(org) -> Optional[str]:
    """
    Find the audit/security tooling account in the organization.

    Args:
        org: The Organization object

    Returns:
        Optional[str]: The account ID if found, None otherwise
    """
    for account in org.get_accounts():
        if account.name.lower() in ["audit", "security tooling"]:
            return account.id
    return None


def check_deploy_log_analysis_tools_in_audit_account() -> Dict[str, Any]:
    """
    Check if log analysis tools are deployed in the audit/security tooling account.

    This check:
    1. Verifies if an organization exists
    2. Looks for an account named either 'Audit' or 'Security Tooling'
    3. Prompts the user to verify if log analysis tools are deployed in that account

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    # Check if organization exists
    org = get_organization()
    if not org:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "No AWS Organization found. This check requires an organization."
                ),
            },
        }

    # Find audit account
    audit_account_id = _find_audit_account(org)

    # Create the message for the panel
    if audit_account_id:
        message = (
            f"Found audit/security tooling account with ID: {audit_account_id}\n\n"
            "Consider the following factors for log analysis tools:\n"
            "- Are log analysis tools (e.g., Athena, OpenSearch, etc.) "
            "deployed in this account?\n"
            "- Are the tools properly configured to ingest logs from the log "
            "archive account?"
        )
    else:
        message = (
            "No account named 'Audit' or 'Security Tooling' was found in the "
            "organization.\n\n"
            "Consider the following factors for log analysis tools:\n"
            "- Are log analysis tools (e.g., Athena, OpenSearch, etc.) "
            "deployed in a dedicated security tooling account?\n"
            "- Are the tools properly configured to ingest logs from the log "
            "archive account?"
        )

    # Use manual_check to get the user's response
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are log analysis tools deployed in the audit/security tooling account?"
        ),
        pass_message="Log analysis tools are properly deployed in the audit account.",
        fail_message="Log analysis tools need to be deployed in the audit account.",
        default=False,
    )


check_deploy_log_analysis_tools_in_audit_account._CHECK_ID = CHECK_ID
check_deploy_log_analysis_tools_in_audit_account._CHECK_NAME = CHECK_NAME
