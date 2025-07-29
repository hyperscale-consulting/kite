from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class TokenizationAndAnonymizationCheck:
    def __init__(self):
        self.check_id = "tokenization-and-anonymization"
        self.check_name = "Tokenization and anonymization techniques"

    @property
    def question(self) -> str:
        return (
            "Are tokenization and anonymization techniques used to reduce data "
            "sensitivity levels where appropriate?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that appropriate techniques are used to reduce data "
            "sensitivity levels."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Are tokenization techniques used to replace sensitive data with "
            "non-sensitive tokens?\n"
            "- Is anonymization applied to remove or mask personally identifiable "
            "information?\n"
            "- Is there a process to evaluate when tokenization or anonymization "
            "should be applied?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
