from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class ThreatModelingCheck:
    def __init__(self):
        self.check_id = "threat-modeling"
        self.check_name = "Threat Modeling"

    @property
    def question(self) -> str:
        return "Do teams perform threat modeling regularly?"

    @property
    def description(self) -> str:
        return "This check verifies that teams perform threat modeling regularly."

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Do teams perform threat modeling regularly?\n"
            "- Is threat modeling part of the development process?\n"
            "- Are threat modeling results documented and reviewed?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
