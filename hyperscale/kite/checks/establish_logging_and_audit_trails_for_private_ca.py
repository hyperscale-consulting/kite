from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class EstablishLoggingAndAuditTrailsForPrivateCACheck:
    def __init__(self):
        self.check_id = "establish-logging-and-audit-trails-for-private-ca"
        self.check_name = "Establish Logging and Audit Trails for Private CA"

    @property
    def question(self) -> str:
        return (
            "Are CloudTrail logs monitored for unauthorized activity and are audit "
            "reports listing certificates issued and revoked periodically reviewed?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that logging and audit trails are established for "
            "private CAs."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are CloudTrail logs monitored for unauthorized activity related to "
            "private CAs?\n"
            "- Are alerts configured for suspicious or unauthorized CA operations?\n"
            "- Are audit reports listing certificates issued and revoked periodically "
            "reviewed?\n"
            "- Is there a process to investigate and respond to unauthorized "
            "certificate operations?\n"
            "- Are audit logs retained for a sufficient period to support "
            "investigations?\n"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
