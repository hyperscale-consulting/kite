from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class RootCredentialsSecurityCheck:
    def __init__(self):
        self.check_id = "root-credentials-security"
        self.check_name = "Root Credentials Security"

    @property
    def question(self) -> str:
        return (
            "Are root credentials stored securely and accessed according to proper "
            "procedures?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that root credentials are stored securely and "
            "accessed according to proper procedures."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Are root credentials stored securely? (e.g., password manager for "
            "passwords, safe for MFA devices)\n"
            "- Is a two-person rule in place so that no single person has access to "
            "all necessary credentials for the root account?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
