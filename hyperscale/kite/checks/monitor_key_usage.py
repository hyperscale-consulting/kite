from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class MonitorKeyUsageCheck:
    def __init__(self):
        self.check_id = "monitor-key-usage"
        self.check_name = "Monitor Key Usage"

    @property
    def question(self) -> str:
        return (
            "Is key usage audited, with monitoring set up to detect and alert on "
            "unusual access patterns and important cryptographic events?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that key usage is audited and monitored for unusual "
            "patterns and important cryptographic events."
        )

    def run(self) -> CheckResult:
        message = (
            "Examples of events to monitor for include:\n"
            "- Key deletion\n"
            "- Rotation of key material\n"
            "- Imported key material nearing its expiry date\n"
            "- High rates of decryption failures"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
