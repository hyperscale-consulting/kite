from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class IdentityAuditCheck:
    def __init__(self):
        self.check_id = "identity-audit"
        self.check_name = "Identity Audit"

    @property
    def question(self) -> str:
        return "Are credentials and identities regularly audited?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that credentials and identities are regularly audited."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider whether IAM users / Identity Center users / IdP users are "
            "regularly reviewed to ensure that only authorized users have access."
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
