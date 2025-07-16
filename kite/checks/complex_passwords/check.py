from typing import Any

from kite.config import Config
from kite.data import get_cognito_user_pools
from kite.data import get_oidc_providers
from kite.data import get_saml_providers
from kite.helpers import get_account_ids_in_scope
from kite.helpers import get_password_policy
from kite.helpers import get_user_pool_password_policy
from kite.helpers import is_cognito_password_policy_complex
from kite.helpers import is_complex
from kite.helpers import is_identity_center_enabled
from kite.helpers import is_identity_center_identity_store_used
from kite.helpers import manual_check

CHECK_ID = "complex-passwords"
CHECK_NAME = "Complex Passwords"


def check_complex_passwords() -> dict[str, Any]:
    """
    Check if complex passwords are enforced across all accounts.

    This check:
    1. Lists all OIDC providers, SAML providers, and Identity Center status
    2. Lists all Cognito user pools and their password policies
    3. Checks password policy complexity for each account in scope
    4. Prompts the user to confirm if complex passwords are enforced

    Returns:
        Dict containing the check results.
    """
    config = Config.get()
    # Get all providers and Identity Center status
    oidc_providers = get_oidc_providers(config.management_account_id)
    saml_providers = get_saml_providers(config.management_account_id)
    identity_center_enabled = is_identity_center_enabled()
    identity_center_identity_store_used = is_identity_center_identity_store_used()

    # Build the message showing current configuration
    message = "Please check for the enforcement of complex passwords\n\n"
    message += "For the purposes of this check, a complex password is defined as a "
    message += "password that:\n"
    message += "- Is at least 8 characters long\n"
    message += "- Contains at least one uppercase letter\n"
    message += "- Contains at least one lowercase letter\n"
    message += "- Contains at least one number\n"
    message += "- Contains at least one special character\n\n"
    message += "Note that Identity Center password policies are not configurable, and"
    message += " meet our definition of 'complex'\n\n"
    message += "Current sign-in configuration:\n\n"

    if saml_providers:
        message += "SAML Providers:\n"
        for provider in saml_providers:
            message += f"- {provider['Arn']}\n"
            if "ValidUntil" in provider:
                message += f"  Valid until: {provider['ValidUntil']}\n"
    else:
        message += "No SAML providers configured\n"

    message += "\n"

    if oidc_providers:
        message += "OIDC Providers:\n"
        for provider in oidc_providers:
            message += f"- {provider['Arn']}\n"
            if "Url" in provider:
                message += f"  URL: {provider['Url']}\n"
    else:
        message += "No OIDC providers configured\n"

    message += "\n"
    message += f"Identity Center Enabled: {identity_center_enabled}\n"
    message += "Identity Center Identity Store used: "
    message += f"{identity_center_identity_store_used}\n\n"

    # Check Cognito user pools
    account_ids = get_account_ids_in_scope()
    non_complex_cognito_pools = []

    for account_id in account_ids:
        for region in Config.get().active_regions:
            user_pools = get_cognito_user_pools(account_id, region)
            for pool in user_pools:
                policy = get_user_pool_password_policy(account_id, region, pool["Id"])
                if not is_cognito_password_policy_complex(policy):
                    non_complex_cognito_pools.append(
                        f"{account_id}: {pool.get('Name', 'Unknown')}"
                    )

    if non_complex_cognito_pools:
        message += "Cognito User Pools with non-complex password policies:\n"
        for pool in non_complex_cognito_pools:
            message += f"- {pool}\n"
        message += "\n"

    # Check IAM password policies
    non_complex_accounts = []

    for account_id in account_ids:
        policy = get_password_policy(account_id)
        print(policy)
        if not is_complex(policy):
            non_complex_accounts.append(account_id)

    if non_complex_accounts:
        message += "Accounts with non-complex IAM password policies:\n"
        for account_id in non_complex_accounts:
            message += f"- {account_id}\n"

    # Run the manual check
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt="Are complex passwords enforced?",
        pass_message="Complex passwords are enforced across all accounts.",
        fail_message="Complex passwords are not enforced across all accounts.",
        default=True,
    )


check_complex_passwords._CHECK_ID = CHECK_ID
check_complex_passwords._CHECK_NAME = CHECK_NAME
