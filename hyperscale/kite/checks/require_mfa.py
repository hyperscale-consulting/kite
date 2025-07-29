from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_cognito_user_pools
from hyperscale.kite.data import get_credentials_report
from hyperscale.kite.data import get_saml_providers
from hyperscale.kite.helpers import get_account_ids_in_scope
from hyperscale.kite.helpers import get_user_pool_mfa_config
from hyperscale.kite.helpers import is_identity_center_enabled


class RequireMfaCheck:
    def __init__(self):
        self.check_id = "require-mfa"
        self.check_name = "Require MFA"

    @property
    def question(self) -> str:
        return "Is MFA required for AWS access?"

    @property
    def description(self) -> str:
        return "This check verifies that MFA is required for AWS access."

    def run(self) -> CheckResult:
        saml_providers = []
        for account_id in get_account_ids_in_scope():
            saml_providers.extend(get_saml_providers(account_id))
        identity_center_enabled = is_identity_center_enabled()
        context_message = ""
        if saml_providers:
            context_message += "SAML Providers Found:\n"
            for provider in saml_providers:
                context_message += f"- {provider['Arn']}\n"
        else:
            context_message += "No SAML providers configured\n"
        context_message += "\n"
        context_message += (
            f"Identity Center enabled: {'Yes' if identity_center_enabled else 'No'}\n"
        )
        iam_users_found = False
        context_message += "\nIAM Users without MFA:\n"
        users_without_mfa = []
        for account_id in get_account_ids_in_scope():
            report = get_credentials_report(account_id)
            for user in report["users"]:
                iam_users_found = True
                if user.get("mfa_active", "false").lower() != "true":
                    users_without_mfa.append(f"{user['user']} ({account_id})")
        if users_without_mfa:
            context_message += "\n".join(f"- {user}" for user in users_without_mfa)
        else:
            context_message += "No IAM users found without MFA enabled"
        if iam_users_found:
            context_message += "\n\n"
            context_message += (
                "IAM Users were found. Confirm that a policy exists "
                "to require MFA for all users.\n"
            )
        context_message += "\n\nCognito User Pools without MFA Required:\n"
        pools_without_mfa = []
        for account_id in get_account_ids_in_scope():
            for region in Config.get().active_regions:
                user_pools = get_cognito_user_pools(account_id, region)
                for pool in user_pools:
                    mfa_config = get_user_pool_mfa_config(
                        account_id, region, pool["Id"]
                    )
                    if mfa_config != "ON":
                        pools_without_mfa.append(
                            f"{pool.get('Name', 'Unknown')} ({account_id}) - "
                            f"MFA: {mfa_config}"
                        )
        if pools_without_mfa:
            context_message += "\n".join(f"- {pool}" for pool in pools_without_mfa)
        else:
            context_message += "No Cognito user pools found without MFA required"
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context_message,
        )
