from typing import Any

from botocore.exceptions import ClientError

from kite.config import Config
from kite.data import get_cognito_user_pools
from kite.data import get_credentials_report
from kite.data import get_oidc_providers
from kite.data import get_saml_providers
from kite.helpers import get_account_ids_in_scope
from kite.helpers import get_user_pool_mfa_config
from kite.helpers import is_identity_center_enabled
from kite.helpers import manual_check

CHECK_ID = "require-mfa"
CHECK_NAME = "Require MFA"


def check_require_mfa() -> dict[str, Any]:
    """
    Check if MFA is required for AWS access.

    This check:
    1. Gathers information about SAML and OIDC providers
    2. Checks if Identity Center is enabled
    3. Lists IAM users without MFA enabled
    4. Asks the user if MFA is required for AWS access

    Returns:
        Dict containing the check results.
    """
    # Track if we encountered any errors
    error_message = None
    config = Config.get()

    try:
        saml_providers = get_saml_providers(config.management_account_id)
    except ClientError as e:
        saml_providers = []
        error_message = f"Error checking SAML providers: {str(e)}"

    try:
        oidc_providers = get_oidc_providers(config.management_account_id)
    except ClientError as e:
        oidc_providers = []
        if error_message:
            error_message += f"\nError checking OIDC providers: {str(e)}"
        else:
            error_message = f"Error checking OIDC providers: {str(e)}"

    try:
        identity_center_enabled = is_identity_center_enabled()
    except ClientError as e:
        identity_center_enabled = False
        if error_message:
            error_message += f"\nError checking Identity Center status: {str(e)}"
        else:
            error_message = f"Error checking Identity Center status: {str(e)}"

    # If we encountered any errors, return an ERROR status
    if error_message:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {"message": error_message},
        }

    # Build the context message
    context_message = "Current IdPs:\n\n"

    if saml_providers:
        context_message += "SAML Providers:\n"
        for provider in saml_providers:
            context_message += f"- {provider['Arn']}\n"
            if "ValidUntil" in provider:
                context_message += f"  Valid until: {provider['ValidUntil']}\n"
    else:
        context_message += "No SAML providers configured\n"

    context_message += "\n"

    if oidc_providers:
        context_message += "OIDC Providers:\n"
        for provider in oidc_providers:
            context_message += f"- {provider['Arn']}\n"
            if "Url" in provider:
                context_message += f"  URL: {provider['Url']}\n"
    else:
        context_message += "No OIDC providers configured\n"

    context_message += "\n"
    context_message += (
        f"Identity Center enabled: {'Yes' if identity_center_enabled else 'No'}\n"
    )

    iam_users_found = False

    # Check for IAM users without MFA
    context_message += "\nIAM Users without MFA:\n"
    users_without_mfa = []
    for account_id in get_account_ids_in_scope():
        try:
            report = get_credentials_report(account_id)
            for user in report["users"]:
                iam_users_found = True
                if user.get("mfa_active", "false").lower() != "true":
                    users_without_mfa.append(f"{user['user']} ({account_id})")
        except Exception as e:
            users_without_mfa.append(
                f"Error getting credentials report for account {account_id}: {str(e)}"
            )

    if users_without_mfa:
        context_message += "\n".join(f"- {user}" for user in users_without_mfa)
    else:
        context_message += "No IAM users found without MFA enabled"

    if iam_users_found:
        context_message += "\n\n"
        context_message += "IAM Users were found. Confirm that a policy exists "
        context_message += "to require MFA for all users.\n"

    # Check Cognito user pools
    context_message += "\n\nCognito User Pools without MFA Required:\n"
    pools_without_mfa = []
    for account_id in get_account_ids_in_scope():
        for region in Config.get().active_regions:
            user_pools = get_cognito_user_pools(account_id, region)
            for pool in user_pools:
                mfa_config = get_user_pool_mfa_config(account_id, region, pool["Id"])
                if mfa_config != "ON":
                    pools_without_mfa.append(
                        f"{pool.get('Name', 'Unknown')} ({account_id}) - "
                        f"MFA: {mfa_config}"
                    )

    if pools_without_mfa:
        context_message += "\n".join(f"- {pool}" for pool in pools_without_mfa)
    else:
        context_message += "No Cognito user pools found without MFA required"

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=context_message,
        prompt="Is MFA required for AWS access?",
        pass_message="MFA is required for AWS access",
        fail_message="MFA is not required for AWS access",
        default=True,
    )


# Attach the check ID and name to the function
check_require_mfa._CHECK_ID = CHECK_ID
check_require_mfa._CHECK_NAME = CHECK_NAME
