from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_organization_features


class AccurateAccountContactDetailsCheck:
    def __init__(self):
        self.check_id = "accurate-account-contact-details"
        self.check_name = "Accurate Account Contact Details"

    @property
    def question(self) -> str:
        return (
            "Are the contact details for the management account (or all accounts) "
            "accurate and secure?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that account contact details are accurate and secure. "
            "If root credentials management is enabled at the org level, only the "
            "management account contact details need to be verified. Otherwise, all "
            "account contact details need to be verified."
        )

    def run(self) -> CheckResult:
        context = ""
        if Config.get().management_account_id:
            # we only fetch organizational features if we have a management account
            features = get_organization_features()
            root_credentials_managed = "RootCredentialsManagement" in features
            if root_credentials_managed:
                context = (
                    "Root credentials management is enabled at the org level. "
                    "Verify the contact details for the management account only."
                    "\n\n"
                )
            else:
                context = (
                    "Root credentials management is not enabled at the org level. "
                    "Verify the contact details for all accounts in scope.\n\n"
                )

        context += (
            "Consider the following factors:\n"
            "- Are contact details accurate and up-to-date?\n"
            "- Is the email address on a corporate domain and a distribution "
            "list locked down to appropriate users?\n"
            "- Is the phone number a secure phone dedicated for this purpose?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
