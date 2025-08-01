from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_saml_providers
from hyperscale.kite.helpers import get_account_ids_in_scope
from hyperscale.kite.helpers import is_identity_center_enabled


class HrSystemIntegrationCheck:
    def __init__(self):
        self.check_id = "hr-idp-integration"
        self.check_name = "HR / IdP Integration"

    @property
    def question(self) -> str:
        return (
            "Are your HR systems integrated with your identity provider to "
            "automatically synchronize personnel changes?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that your HR systems are integrated with your "
            "external identity provider to automatically synchronize personnel changes."
        )

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
        context_message += "\n\n"
        context_message += (
            f"Identity Center enabled: {'Yes' if identity_center_enabled else 'No'}\n"
        )
        context_message += "\n"
        context_message += (
            "Consider the following factors:\n"
            "- Are joiners automatically provisioned with appropriate access?\n"
            "- Are leavers automatically deprovisioned?\n"
            "- Are role changes automatically reflected in access permissions?\n"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context_message,
        )
