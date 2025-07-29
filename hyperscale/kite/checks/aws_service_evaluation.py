from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class AwsServiceEvaluationCheck:
    def __init__(self):
        self.check_id = "aws-service-evaluation"
        self.check_name = "AWS Service Evaluation"

    @property
    def question(self) -> str:
        return (
            "Do teams keep up to date with the launch of new AWS services and evaluate "
            "their potential for use?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that teams keep up to date with the launch of new "
            "AWS services and evaluate their potential for use."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Do teams regularly review new AWS service launches?\n"
            "- Do teams evaluate the potential benefits of new services?\n"
            "- Do teams consider migrating to new services where appropriate?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
