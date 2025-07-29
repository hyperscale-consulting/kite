from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class SecurityRisksCheck:
    def __init__(self):
        self.check_id = "security-risks"
        self.check_name = "Security Risks"

    @property
    def question(self) -> str:
        return (
            "Have teams done a good job at identifying (and addressing) security risks?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that teams have done a good job at identifying and "
            "addressing security risks."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Have teams identified security risks - are there any obvious STRIDE "
            "threats missing?\n"
            "- Have teams addressed identified security risks? For example, have they "
            "been tracked as bugs and fixed? Are those mitigations suitable?\n"
            "- Is the process for identifying and addressing risks effective?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
