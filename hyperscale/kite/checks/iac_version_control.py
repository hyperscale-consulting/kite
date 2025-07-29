"""Check for IaC templates stored in version control with CI/CD testing."""

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class IacVersionControlCheck:
    def __init__(self):
        self.check_id = "iac-version-control"
        self.check_name = "IaC Version Control"

    @property
    def question(self) -> str:
        return (
            "Are IaC templates stored in version control, tested as part of a CI/CD "
            "pipeline and automatically deployed to production?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that IaC templates are stored in version control, "
            "tested as part of a CI/CD pipeline and automatically deployed to "
            "production."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are IaC templates stored in version control?\n"
            "- Are IaC templates tested as part of a CI/CD pipeline?\n"
            "- Are IaC templates automatically deployed to production?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
