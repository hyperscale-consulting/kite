from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_cognito_user_pools
from hyperscale.kite.data import get_oidc_providers
from hyperscale.kite.data import get_saml_providers
from hyperscale.kite.helpers import get_account_ids_in_scope
from hyperscale.kite.helpers import get_password_policy
from hyperscale.kite.helpers import get_user_pool_password_policy
from hyperscale.kite.helpers import is_cognito_password_policy_complex
from hyperscale.kite.helpers import is_complex
from hyperscale.kite.helpers import is_identity_center_enabled
from hyperscale.kite.helpers import is_identity_center_identity_store_used


class ComplexPasswordsCheck:
    def __init__(self):
        self.check_id = "complex-passwords"
        self.check_name = "Complex Passwords"

    @property
    def question(self) -> str:
        return "Are complex passwords enforced across all accounts?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that complex passwords are enforced across all "
            "accounts, including IAM, Cognito, and federated providers."
        )

    def run(self) -> CheckResult:
        config = Config.get()
        oidc_providers = (
            get_oidc_providers(config.management_account_id)
            if config.management_account_id
            else []
        )
        saml_providers = (
            get_saml_providers(config.management_account_id)
            if config.management_account_id
            else []
        )
        identity_center_enabled = is_identity_center_enabled()
        identity_center_identity_store_used = is_identity_center_identity_store_used()
        message = "Please check for the enforcement of complex passwords\n\n"
        message += "For the purposes of this check, a complex password is defined as a "
        message += "password that:\n"
        message += "- Is at least 8 characters long\n"
        message += "- Contains at least one uppercase letter\n"
        message += "- Contains at least one lowercase letter\n"
        message += "- Contains at least one number\n"
        message += "- Contains at least one special character\n\n"
        message += (
            "Note that Identity Center password policies are not configurable, and"
        )
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
        account_ids = get_account_ids_in_scope()
        non_complex_cognito_pools = []
        for account_id in account_ids:
            for region in Config.get().active_regions:
                user_pools = get_cognito_user_pools(account_id, region)
                for pool in user_pools:
                    policy = get_user_pool_password_policy(
                        account_id, region, pool["Id"]
                    )
                    if not is_cognito_password_policy_complex(policy):
                        non_complex_cognito_pools.append(
                            f"{account_id}: {pool.get('Name', 'Unknown')}"
                        )
        if non_complex_cognito_pools:
            message += "Cognito User Pools with non-complex password policies:\n"
            for pool in non_complex_cognito_pools:
                message += f"- {pool}\n"
            message += "\n"
        non_complex_accounts = []
        for account_id in account_ids:
            policy = get_password_policy(account_id)
            if not is_complex(policy):
                non_complex_accounts.append(account_id)
        if non_complex_accounts:
            message += "Accounts with non-complex IAM password policies:\n"
            for account_id in non_complex_accounts:
                message += f"- {account_id}\n"
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
