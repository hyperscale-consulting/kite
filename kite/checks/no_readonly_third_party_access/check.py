"""Check for IAM roles with cross-account readonly access policies."""

from typing import Any

from kite.data import get_organization
from kite.data import get_roles
from kite.helpers import get_prowler_output

CHECK_ID = "no-readonly-third-party-access"
CHECK_NAME = "No Readonly Third Party Access"


def _is_principal_in_organization(principal: str, org_account_ids: set[str]) -> bool:
    """
    Check if a principal is from an account within the organization.

    Args:
        principal: The principal ARN to check
        org_account_ids: Set of account IDs in the organization

    Returns:
        bool: True if the principal is from an account within the organization
    """
    # Extract account ID from principal ARN
    try:
        account_id = principal.split(":")[4]
        return account_id in org_account_ids
    except (IndexError, AttributeError):
        return False


def check_no_readonly_third_party_access() -> dict[str, Any]:
    """
    Check if IAM roles have cross-account readonly access policies.

    This check verifies that IAM roles do not have cross-account readonly access
    policies by checking Prowler results for the following check ID:
    - iam_role_cross_account_readonlyaccess_policy

    The check will fail if:
    1. The account is not part of an organization
    2. The role can be assumed by principals outside the organization

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - failing_resources: List of resources that failed the check
    """
    # Get Prowler results
    prowler_results = get_prowler_output()

    # The check ID we're interested in
    check_id = "iam_role_cross_account_readonlyaccess_policy"

    # Track failing resources
    failing_resources: list[dict[str, Any]] = []

    # Check results for the check ID
    if check_id in prowler_results:
        # Get results for this check ID
        results = prowler_results[check_id]

        # Get organization data
        org = get_organization()
        if org is None:
            # If not in an organization, all findings are valid
            for result in results:
                if result.status != "PASS":
                    failing_resources.append(
                        {
                            "account_id": result.account_id,
                            "resource_uid": result.resource_uid,
                            "resource_name": result.resource_name,
                            "resource_details": result.resource_details,
                            "region": result.region,
                            "status": result.status,
                        }
                    )
        else:
            # Get all account IDs in the organization
            org_account_ids = {account.id for account in org.get_accounts()}

            # Check each failing result
            for result in results:
                if result.status != "PASS":
                    # Get the role data which includes AssumeRolePolicyDocument
                    roles = get_roles(result.account_id)
                    role = next(
                        (r for r in roles if r["RoleId"] == result.resource_uid), None
                    )

                    if role is None:
                        continue

                    # Check if any principal in the trust policy is from outside the org
                    has_external_principal = False
                    for statement in role["AssumeRolePolicyDocument"].get(
                        "Statement", []
                    ):
                        if statement.get("Effect") == "Allow":
                            principals = statement.get("Principal", {})
                            if isinstance(principals, dict):
                                for (
                                    principal_type,
                                    principal_value,
                                ) in principals.items():
                                    if isinstance(principal_value, list):
                                        for principal in principal_value:
                                            if not _is_principal_in_organization(
                                                principal, org_account_ids
                                            ):
                                                has_external_principal = True
                                                break
                                    elif isinstance(principal_value, str):
                                        if not _is_principal_in_organization(
                                            principal_value, org_account_ids
                                        ):
                                            has_external_principal = True
                                            break

                    # Only add to failing resources if there's an external principal
                    if has_external_principal:
                        failing_resources.append(
                            {
                                "account_id": result.account_id,
                                "resource_uid": result.resource_uid,
                                "resource_name": result.resource_name,
                                "resource_details": (
                                    "Role can be assumed by principals outside the "
                                    "organization"
                                ),
                                "region": result.region,
                                "status": result.status,
                            }
                        )

    # Determine if the check passed
    passed = len(failing_resources) == 0

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS" if passed else "FAIL",
        "details": {
            "message": (
                "No IAM roles were found with cross-account readonly access policies."
                if passed
                else (
                    f"Found {len(failing_resources)} IAM roles with cross-account "
                    "readonly access policies."
                )
            ),
            "failing_resources": failing_resources,
        },
    }


# Attach the check ID and name to the function
check_no_readonly_third_party_access._CHECK_ID = CHECK_ID
check_no_readonly_third_party_access._CHECK_NAME = CHECK_NAME
