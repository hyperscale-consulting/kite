from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class ControlTowerCheck:
    def __init__(self):
        self.check_id = "control-tower"
        self.check_name = "Control Tower"

    @property
    def question(self) -> str:
        return "Is Control Tower used to enable suitable standard controls?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that Control Tower is used to enable suitable "
            "standard controls."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Is Control Tower used to enable standard controls?\n"
            "- Are the standard controls suitable for the organization?\n"
            "- Are the standard controls consistently applied across all accounts?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
