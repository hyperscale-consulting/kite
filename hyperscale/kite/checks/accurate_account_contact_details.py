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
            "This check verifies that account contact details are accurate and, and "
            "that the related email addresses and phone numbers are secures "
            "appropriately."
        )

    def run(self) -> CheckResult:
        context = ""
        if Config.get().management_account_id:
            # we only fetch organizational features if we have a management account
            features = get_organization_features()
            root_credentials_managed = "RootCredentialsManagement" in features
            if root_credentials_managed:
                context = (
                    "Root credentials management is enabled at the organizational "
                    "level, so you only need to verify contact details for the "
                    "management account.\n\n"
                )
            else:
                context = (
                    "Root credentials management is *not* enabled at the organizational"
                    " level. You will need to verify the contact details for all "
                    "member accounts in scope for the assessment.\n\n"
                )

        context += (
            "Consider the following:\n"
            "- Are contact details accurate and up-to-date?\n"
            "- Is the email address on a corporate domain and a distribution "
            "list locked down to appropriate users (e.g. cloud admins)?\n"
            "- Is the phone number pointing to a suitably secured phone (e.g. "
            "dedicated for this purpose, number kept private, kept in a secure "
            "location)?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
