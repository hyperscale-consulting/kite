"""Check if administrator privileges are restricted to a small, trusted group."""

from typing import Dict, Any, List

from kite.data import (
    get_saml_providers,
    get_roles,
    get_policy_document,
    get_customer_managed_policies,
    get_inline_policy_document,
)
from kite.helpers import get_account_ids_in_scope, manual_check


CHECK_ID = "admin-privileges-are-restricted"
CHECK_NAME = "Admin Privileges Are Restricted"


def _is_admin_policy(policy_doc: Dict[str, Any]) -> bool:
    """
    Check if a policy document grants administrator privileges.

    Args:
        policy_doc: The policy document to check

    Returns:
        bool: True if the policy grants administrator privileges
    """
    for statement in policy_doc.get("Statement", []):
        if (
            statement.get("Effect") == "Allow"
            and statement.get("Action") == "*"
            and statement.get("Resource") == "*"
        ):
            return True
    return False


def _is_service_linked_role(role: Dict[str, Any]) -> bool:
    """
    Check if a role is a service-linked role.

    A role is considered a service-linked role if:
    1. Its path starts with '/aws-service-role/', or
    2. Its assume role policy has a principal with an ARN containing
       '/aws-service-role/'

    Args:
        role: The role to check

    Returns:
        bool: True if the role is a service-linked role
    """
    # Check role path
    if role.get("Path", "").startswith("/aws-service-role/"):
        return True

    # Check assume role policy
    assume_role_policy = role.get("AssumeRolePolicyDocument", {})
    for statement in assume_role_policy.get("Statement", []):
        principal = statement.get("Principal", {})
        if isinstance(principal, dict):
            # Check AWS principal ARN
            aws_principal = principal.get("AWS", "")
            if isinstance(aws_principal, str) and "/aws-service-role/" in aws_principal:
                return True
            # Check list of AWS principal ARNs
            if isinstance(aws_principal, list):
                for arn in aws_principal:
                    if isinstance(arn, str) and "/aws-service-role/" in arn:
                        return True

    return False


def check_admin_privileges_are_restricted() -> Dict[str, Any]:
    """
    Check if administrator privileges are restricted to a small, trusted group.

    This check presents to the user:
    1. A list of SAML providers registered in the account
    2. A list of roles that have administrator privileges (Action: "*" and
       Resource: "*"), excluding AWS service-linked roles

    The user must then decide if these administrator privileges are restricted to
    a small, trusted group.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - saml_providers: List of SAML providers
                - admin_roles: List of roles with administrator privileges
    """
    # Track SAML providers and admin roles
    saml_providers: List[Dict[str, Any]] = []
    admin_roles: List[Dict[str, Any]] = []

    # Get SAML providers
    providers = get_saml_providers()
    if providers:
        for provider in providers:
            saml_providers.append({
                "arn": provider["Arn"],
                "valid_until": provider.get("ValidUntil"),
                "create_date": provider["CreateDate"],
            })

    # Get roles with admin privileges for each account
    for account_id in get_account_ids_in_scope():
        roles = get_roles(account_id)
        customer_policies = get_customer_managed_policies(account_id)

        for role in roles:
            # Skip service-linked roles
            if _is_service_linked_role(role):
                continue

            has_admin_access = False
            admin_policy_info = None

            # Check attached policies
            for policy in role.get("AttachedPolicies", []):
                policy_arn = policy["PolicyArn"]
                # Check for AWS managed AdministratorAccess policy
                if policy_arn.endswith("AdministratorAccess"):
                    has_admin_access = True
                    admin_policy_info = {
                        "policy_name": "AdministratorAccess",
                        "policy_arn": policy_arn,
                        "policy_type": "aws_managed",
                    }
                    break

                # Check customer managed policies
                for customer_policy in customer_policies:
                    if customer_policy["Arn"] == policy_arn:
                        policy_doc = get_policy_document(account_id, policy_arn)
                        if policy_doc and _is_admin_policy(policy_doc):
                            has_admin_access = True
                            admin_policy_info = {
                                "policy_name": customer_policy["Name"],
                                "policy_arn": policy_arn,
                                "policy_type": "customer_managed",
                            }
                            break
                    if has_admin_access:
                        break

            # Check inline policies
            if not has_admin_access:
                for policy_name in role.get("InlinePolicyNames", []):
                    policy_doc = get_inline_policy_document(
                        account_id, role["RoleName"], policy_name
                    )
                    if policy_doc and _is_admin_policy(policy_doc):
                        has_admin_access = True
                        admin_policy_info = {
                            "policy_name": policy_name,
                            "policy_type": "inline",
                        }
                        break

            if has_admin_access and admin_policy_info:
                admin_roles.append({
                    "account_id": account_id,
                    "role_name": role["RoleName"],
                    "role_arn": role["Arn"],
                    **admin_policy_info,
                })

    # Build message for manual check
    message = "SAML Providers:\n\n"
    if saml_providers:
        for provider in saml_providers:
            message += f"ARN: {provider['arn']}\n"
            if provider.get("valid_until"):
                message += f"Valid until: {provider['valid_until']}\n"
            message += f"Created: {provider['create_date']}\n\n"
    else:
        message += "No SAML providers configured\n\n"

    message += (
        "Roles with Administrator Privileges "
        "(excluding AWS service-linked roles):\n\n"
    )
    if admin_roles:
        for role in admin_roles:
            message += f"Account: {role['account_id']}\n"
            message += f"Role Name: {role['role_name']}\n"
            message += f"Role ARN: {role['role_arn']}\n"
            if "policy_arn" in role:
                message += f"Policy ARN: {role['policy_arn']}\n"
            message += f"Policy Name: {role['policy_name']}\n"
            message += f"Policy Type: {role['policy_type']}\n"
            message += "\n"
    else:
        message += "No roles found with administrator privileges\n\n"

    # Ask user to verify
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are administrator privileges restricted to a small, trusted group? "
            "Consider the SAML providers and roles listed above."
        ),
        pass_message=(
            "Administrator privileges are appropriately restricted to a small, "
            "trusted group."
        ),
        fail_message=(
            "Administrator privileges should be restricted to a small, trusted "
            "group. Review the SAML providers and roles listed above."
        ),
        default=False,
    )

    # Add the details to the result
    if "details" in result:
        result["details"]["saml_providers"] = saml_providers
        result["details"]["admin_roles"] = admin_roles

    return result


# Attach the check ID and name to the function
check_admin_privileges_are_restricted._CHECK_ID = CHECK_ID
check_admin_privileges_are_restricted._CHECK_NAME = CHECK_NAME
