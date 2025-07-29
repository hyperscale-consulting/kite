from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class PerformDASTCheck:
    def __init__(self):
        self.check_id = "perform-dast"
        self.check_name = "Perform Dynamic Application Security Testing"

    @property
    def question(self) -> str:
        return "Is DAST used to detect potential runtime security issues?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that DAST is used to detect potential runtime "
            "security issues."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors regarding you use of DAST (Dynamic "
            "Application Security Testing):\n"
            "- Is DAST integrated into the development pipeline?\n"
            "- Are DAST results reviewed and acted upon in a timely manner?\n"
            "- Are false positives managed and minimized?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
