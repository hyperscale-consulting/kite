from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class SecurityGuardiansProgramCheck:
    def __init__(self):
        self.check_id = "security-guardians-program"
        self.check_name = "Security Guardians Program"

    @property
    def question(self) -> str:
        return (
            "Is there a program to embed security ownership and decision making in "
            "workload teams?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that there is a program to embed security ownership "
            "and decision making in workload teams."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Is there a formal program to embed security expertise in teams?\n"
            "- Do teams have clear ownership of security decisions?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
