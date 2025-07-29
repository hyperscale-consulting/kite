from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class RunSimulationsCheck:
    def __init__(self):
        self.check_id = "run-simulations"
        self.check_name = "Run Security Event Simulations"

    @property
    def question(self) -> str:
        return (
            "Do you run regular simulations of real-world security event "
            "scenarios designed to exercise and evaluate incident response "
            "capabilities?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that regular simulations of real-world security "
            "event scenarios are conducted to exercise and evaluate incident "
            "response capabilities."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Are simulations conducted on a regular schedule (e.g., quarterly)?\n"
            "- Do simulations cover realistic threat scenarios?\n"
            "- Are different types of incidents simulated (e.g., data breach, "
            "ransomware, insider threat)?\n"
            "- Do simulations test both technical and procedural response "
            "capabilities?\n"
            "- Are lessons learned documented and incorporated into response plans?\n"
            "- Do simulations involve cross-functional teams?\n"
            "- Are simulations designed to test communication and escalation "
            "procedures?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
