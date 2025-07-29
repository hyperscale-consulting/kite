from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class MacieScansForSensitiveDataCheck:
    def __init__(self):
        self.check_id = "macie-scans-for-sensitive-data"
        self.check_name = "Macie Scans for Sensitive Data"

    @property
    def question(self) -> str:
        return "Is Macie used to scan for sensitive data across workloads?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that Macie is used to scan for sensitive data across "
            "workloads."
        )

    def run(self) -> CheckResult:
        message = (
            "Note that data can be exported from data sources such as RDS and DynamoDB "
            "into an S3 bucket for scanning by Macie."
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
