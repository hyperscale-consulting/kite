from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_oidc_providers
from hyperscale.kite.data import get_saml_providers
from hyperscale.kite.helpers import get_account_ids_in_scope
from hyperscale.kite.helpers import is_identity_center_enabled


class UseCentralizedIdpCheck:
    def __init__(self):
        self.check_id = "use-centralized-idp"
        self.check_name = "Use Centralized Identity Provider"

    @property
    def question(self) -> str:
        return (
            "Is a centralized identity provider used across the organization's "
            "applications?"
        )

    @property
    def description(self) -> str:
        return (
            "By using a centralized identity provider, you have a single place to "
            "manage workforce user identities and policies, the ability to assign "
            "access to applications to users and groups, and the ability to monitor "
            "user sign-in activity.\n\n"
            "This check verifies that a centralized identity provider is used "
            "across the organization's applications."
        )

    def run(self) -> CheckResult:
        saml_providers = []
        for account_id in get_account_ids_in_scope():
            saml_providers.extend(get_saml_providers(account_id))

        oidc_providers = []
        for account_id in get_account_ids_in_scope():
            oidc_providers.extend(get_oidc_providers(account_id))

        context_message = "Current IdPs:\n\n"
        if saml_providers:
            context_message += "SAML providers found:\n"
            for provider in saml_providers:
                context_message += f"- {provider['Arn']}\n"
        else:
            context_message += "No SAML providers found\n"

        context_message += "\n"

        if oidc_providers:
            context_message += "OIDC providers found:\n"
            for provider in oidc_providers:
                context_message += f"- {provider['Arn']}\n"
                if "Url" in provider:
                    context_message += f"  URL: {provider['Url']}\n"
        else:
            context_message += "No OIDC providers found\n"

        context_message += "\n"

        identity_center_enabled = is_identity_center_enabled()
        context_message += (
            f"Identity Center enabled: {'Yes' if identity_center_enabled else 'No'}\n"
        )

        return CheckResult(status=CheckStatus.MANUAL, context=context_message)
