from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class SecurityServicesEvaluationCheck:
    def __init__(self):
        self.check_id = "security-services-evaluation"
        self.check_name = "Security Services Evaluation"

    @property
    def question(self) -> str:
        return (
            "Do teams evaluate and implement new security services and features "
            "regularly?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that teams evaluate and implement new security "
            "services and features regularly."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- How do teams keep up to date with new security services and features? "
            "For example, do they subscribe to AWS or partner security blogs?\n"
            "- How are teams within the organisation encouraged to stay on top of "
            "security services and features?\n"
            "- Are innovation / sandbox accounts available for teams to experiment "
            "with?"
        )

        return CheckResult(status=CheckStatus.MANUAL, context=message)
