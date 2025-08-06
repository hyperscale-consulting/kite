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
            "Threat modeling is a simple yet effective way to find and mitigate "
            "threats to your workload. Starting as early as possible in the lifecycle "
            "of your workload means that threats can be addressed most "
            "cost-effectively.\n\n"
            "Consider the following:\n"
            "- Do teams perform threat modeling regularly, e.g. each sprint, or for "
            "each new feature?\n"
            "- Are there up-to-date data-flow diagrams (DFDs) capturing all major "
            "trust boundaries, data flows and components?\n"
            "- Have teams done a good job at identifying and addressing security "
            "risks?\n"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
