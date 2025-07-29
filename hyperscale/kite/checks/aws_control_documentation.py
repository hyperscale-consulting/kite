from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class AwsControlDocumentationCheck:
    def __init__(self):
        self.check_id = "aws-control-documentation"
        self.check_name = "AWS Control Documentation"

    @property
    def question(self) -> str:
        return (
            "Is AWS control and compliance documentation incorporated into control "
            "evaluation and verification procedures?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that AWS control and compliance documentation is "
            "incorporated into control evaluation and verification procedures."
        )

    def run(self) -> CheckResult:
        message = (
            "Is AWS control and compliance documentation incorporated into control "
            "evaluation and verification procedures, thus taking advantage of AWS's "
            "built-in controls and the shared responsibility model."
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
