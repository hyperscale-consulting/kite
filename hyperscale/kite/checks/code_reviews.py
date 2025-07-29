from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class CodeReviewsCheck:
    def __init__(self):
        self.check_id = "conduct-code-reviews"
        self.check_name = "Conduct Code Reviews"

    @property
    def question(self) -> str:
        return (
            "Are code reviews used to detect security vulnerabilities in production "
            "code?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that code reviews are used to detect security "
            "vulnerabilities in production code."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are code reviews mandatory before code is merged to production?\n"
            "- Do code reviews include security-focused checks?\n"
            "- Are reviewers trained to identify common security vulnerabilities?\n"
            "- Are code review checklists and guidelines used?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
