from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class SecureSecretsStorageCheck:
    def __init__(self):
        self.check_id = "secure-secrets-storage"
        self.check_name = "Secure Secrets Storage"

    @property
    def question(self) -> str:
        return (
            "Are all secrets stored in a secure platform (i.e. encrypted, auditable, "
            "etc)?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that all secrets are stored in a secure platform "
            "with proper encryption and audit capabilities."
        )

    def run(self) -> CheckResult:
        context = (
            "Are all secrets are stored in a dedicated secret management service "
            "(e.g. AWS Secrets Manager, HashiCorp Vault, etc) with proper encryption "
            "and audit capabilities."
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
