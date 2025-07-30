from botocore.exceptions import ClientError

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_oidc_providers
from hyperscale.kite.data import get_saml_providers
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
        # Track if we encountered any errors
        error_message = None
        config = Config.get()

        # Check if management account ID is available
        if not config.management_account_id:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="Management account ID is not configured.",
            )

        # Gather information about sign-in mechanisms
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
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=error_message,
            )

        # Build the context message
        context_message = "Current IdPs:\n\n"

        if saml_providers:
            context_message += "SAML Providers:\n"
            for provider in saml_providers:
                context_message += f"- {provider['Arn']}\n"
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

        return CheckResult(status=CheckStatus.MANUAL, context=context_message)
