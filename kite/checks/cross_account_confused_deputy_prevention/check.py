"""Check for sts:ExternalId condition on cross-account role assumptions."""

from typing import Dict, Any, List, Set

from kite.data import get_organization, get_roles
from kite.helpers import get_account_ids_in_scope


CHECK_ID = "cross-account-confused-deputy-prevention"
CHECK_NAME = "Cross-Account Confused Deputy Prevention"


def _is_principal_in_organization(principal: str, org_account_ids: Set[str]) -> bool:
    """
    Check if a principal is from an account within the organization.

    Args:
        principal: The principal ARN to check
        org_account_ids: Set of account IDs in the organization

    Returns:
        bool: True if the principal is from an account within the organization
    """
    # Service principals are always considered internal
    if principal.endswith(".amazonaws.com"):
        return True

    # Extract account ID from principal ARN
    try:
        account_id = principal.split(":")[4]
        return account_id in org_account_ids
    except (IndexError, AttributeError):
        return False


def _has_external_id_condition(statement: Dict[str, Any]) -> bool:
    """
    Check if a statement has the sts:ExternalId condition.

    Args:
        statement: The policy statement to check

    Returns:
        bool: True if the statement has the sts:ExternalId condition
    """
    conditions = statement.get("Condition", {})
    return (
        "StringEquals" in conditions
        and "sts:ExternalId" in conditions["StringEquals"]
    )


def check_cross_account_confused_deputy_prevention() -> Dict[str, Any]:
    """
    Check if cross-account role assumptions have the sts:ExternalId condition.

    This check verifies that any IAM role that can be assumed by principals
    from other accounts has the sts:ExternalId condition in its trust policy.
    This helps prevent confused deputy attacks by requiring an external ID
    that must be known by both the trusting and trusted accounts.

    The check will fail if:
    1. A role can be assumed by principals from other accounts without
       the sts:ExternalId condition

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - failing_resources: List of resources that failed the check
    """
    # Track failing resources
    failing_resources: List[Dict[str, Any]] = []

    # Get organization data
    org = get_organization()
    org_account_ids = {account.id for account in org.get_accounts()}

    # Check each account
    for account_id in get_account_ids_in_scope():
        # Get all roles in the account
        roles = get_roles(account_id)

        # Check each role's trust policy
        for role in roles:
            has_external_principal = False
            has_external_id_condition = False

            # Check each statement in the trust policy
            for statement in role["AssumeRolePolicyDocument"].get("Statement", []):
                if statement.get("Effect") == "Allow":
                    principals = statement.get("Principal", {})
                    if isinstance(principals, dict):
                        for (
                            principal_type,
                            principal_value
                        ) in principals.items():
                            if isinstance(principal_value, list):
                                for principal in principal_value:
                                    if not _is_principal_in_organization(
                                        principal, org_account_ids
                                    ):
                                        has_external_principal = True
                                        if _has_external_id_condition(statement):
                                            has_external_id_condition = True
                                        break
                            elif isinstance(principal_value, str):
                                if not _is_principal_in_organization(
                                    principal_value, org_account_ids
                                ):
                                    has_external_principal = True
                                    if _has_external_id_condition(statement):
                                        has_external_id_condition = True
                                    break

            # If the role can be assumed by external principals but doesn't have
            # the sts:ExternalId condition, it fails the check
            if has_external_principal and not has_external_id_condition:
                failing_resources.append({
                    "account_id": account_id,
                    "resource_uid": role["RoleId"],
                    "resource_name": role["RoleName"],
                    "resource_details": (
                        "Role can be assumed by principals from other accounts "
                        "without the sts:ExternalId condition"
                    ),
                    "region": "global",
                    "status": "FAIL"
                })

    # Determine if the check passed
    passed = len(failing_resources) == 0

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS" if passed else "FAIL",
        "details": {
            "message": (
                "All cross-account role assumptions have the sts:ExternalId "
                "condition."
                if passed
                else (
                    f"Found {len(failing_resources)} roles that can be assumed by "
                    "principals from other accounts without the "
                    "sts:ExternalId condition."
                )
            ),
            "failing_resources": failing_resources,
        },
    }


# Attach the check ID and name to the function
check_cross_account_confused_deputy_prevention._CHECK_ID = CHECK_ID
check_cross_account_confused_deputy_prevention._CHECK_NAME = CHECK_NAME
