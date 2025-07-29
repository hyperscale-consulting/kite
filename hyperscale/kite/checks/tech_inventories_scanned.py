from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class TechInventoriesScannedCheck:
    def __init__(self):
        self.check_id = "tech-inventories-scanned"
        self.check_name = "Technology Inventory Scanning"

    @property
    def question(self) -> str:
        return (
            "Do teams maintain inventories of technology components and continuously "
            "scan them for potential vulnerabilities?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that teams maintain inventories of technology "
            "components and continuously scan them for potential vulnerabilities."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Do teams maintain up-to-date inventories of all technology "
            "components (e.g. SBOMs)?\n"
            "- Are these inventories regularly scanned for vulnerabilities (e.g. "
            "Inspector, ECR scanning)?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
