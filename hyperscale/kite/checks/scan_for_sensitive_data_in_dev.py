from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class ScanForSensitiveDataInDevCheck:
    def __init__(self):
        self.check_id = "scan-for-sensitive-data-in-dev"
        self.check_name = "Scan for Sensitive Data in Development"

    @property
    def question(self) -> str:
        return (
            "Are tools used to automatically scan data for sensitivity while "
            "workloads are in development to alert when sensitive data is "
            "unexpected and prevent further deployment?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that tools are used to automatically scan data "
            "for sensitivity while workloads are in development to alert when "
            "sensitive data is unexpected and prevent further deployment."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Are tools used to scan for sensitive data in development?\n"
            "- Are alerts configured for unexpected sensitive data?\n"
            "- Is deployment prevented when sensitive data is detected?\n"
            "- Do the scans align with your data classification scheme?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
