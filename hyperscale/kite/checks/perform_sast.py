"""Check for performing Static Application Security Testing (SAST)."""

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class PerformSASTCheck:
    def __init__(self):
        self.check_id = "perform-sast"
        self.check_name = "Perform Static Application Security Testing"

    @property
    def question(self) -> str:
        return (
            "Is SAST used to analyze source code for anomalous security patterns and "
            "provide indications for defect prone code?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that SAST is used to analyze source code for "
            "anomalous security patterns and provide indications for defect prone code."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors regarding your use of SAST (Static "
            "Application Security Testing):\n"
            "- Is SAST integrated into the development pipeline?\n"
            "- Is SAST integrated into the developer IDEs?\n"
            "- Are SAST results reviewed and acted upon in a timely manner?\n"
            "- Are false positives managed and minimized?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
