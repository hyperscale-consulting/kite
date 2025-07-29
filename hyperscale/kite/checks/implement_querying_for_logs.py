from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class ImplementQueryingForLogsCheck:
    def __init__(self):
        self.check_id = "implement-querying-for-logs"
        self.check_name = "Log Querying Mechanisms"

    @property
    def question(self) -> str:
        return "Do you have appropriate mechanisms for querying and analyzing logs?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that appropriate mechanisms are in place for querying "
            "and analyzing logs."
        )

    def run(self) -> CheckResult:
        message = (
            "For example, are you using CloudWatch Logs Insights to query logs stored "
            "in CloudWatch log groups? Or Athena, or Amazon OpenSearch for logs "
            "stored in S3? Or a third party SIEM solution?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
