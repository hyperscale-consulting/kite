"""Check for repeatable and auditable setup of third-party access."""

from typing import Dict, Any, List, Set

from kite.data import get_organization, get_roles
from kite.helpers import get_account_ids_in_scope, manual_check


CHECK_ID = "repeatable-auditable-setup-for-3rd-party-access"
CHECK_NAME = "Repeatable and Auditable Setup for Third-Party Access"


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


def check_repeatable_auditable_setup_for_3rd_party_access() -> Dict[str, Any]:
    """
    Check for roles that can be assumed by external principals with ExternalId
    conditions and prompt for review of the setup process.


    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - roles_to_review: List of roles that need review
    """
    # Track roles that need review
    roles_to_review: List[Dict[str, Any]] = []

    # Get organization data
    org = get_organization()
    if org is None:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "AWS Organizations is not being used, so third-party access "
                    "cannot be assessed."
                ),
            },
        }

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

            # If the role can be assumed by external principals and has the
            # sts:ExternalId condition, it needs review
            if has_external_principal and has_external_id_condition:
                roles_to_review.append({
                    "account_id": account_id,
                    "resource_uid": role["RoleId"],
                    "resource_name": role["RoleName"],
                    "resource_details": (
                        "Role can be assumed by external principals and has the "
                        "sts:ExternalId condition. Review the setup process to "
                        "ensure it is repeatable and auditable."
                    ),
                    "region": "global",
                    "status": "REVIEW"
                })

    if not roles_to_review:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "No roles found that can be assumed by external principals "
                    "with ExternalId conditions."
                ),
            },
        }

    # Build message for manual check
    message = (
        f"Found {len(roles_to_review)} roles that can be assumed by external "
        "principals with ExternalId conditions:\n\n"
    )

    for role in roles_to_review:
        message += (
            f"- {role['resource_name']} in account {role['account_id']}\n"
        )

    message += (
        "\nFor each role, review whether there is a repeatable and auditable "
        "process for setting up access, considering:\n"
        "- Is there prescriptive guidance for creating these roles, in particular for "
        "generating a non-guessable ExternalId?\n"
        "- Is role creation automated (e.g., via CloudFormation)?\n"
        "- Can role configuration be checked for drift as part of ongoing audit?"
    )

    # Use manual_check to get user confirmation
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is there a repeatable and auditable process for setting up access "
            "for these third parties?"
        ),
        pass_message=(
            "There is a repeatable and auditable process for setting up access "
            "for third parties."
        ),
        fail_message=(
            "A repeatable and auditable process should be established for setting "
            "up access for third parties."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_repeatable_auditable_setup_for_3rd_party_access._CHECK_ID = CHECK_ID
check_repeatable_auditable_setup_for_3rd_party_access._CHECK_NAME = CHECK_NAME
