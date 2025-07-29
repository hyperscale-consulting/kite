from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class IacTemplatesCheck:
    def __init__(self):
        self.check_id = "iac-templates"
        self.check_name = "IaC Templates"

    @property
    def question(self) -> str:
        return (
            "Are standard security controls and configurations defined using "
            "Infrastructure as Code (IaC) templates?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that standard security controls and configurations "
            "are defined using Infrastructure as Code (IaC) templates.\n\n"
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are standard security controls defined using IaC templates?\n"
            "- Are standard configurations defined using IaC templates?\n"
            "- Are IaC templates used consistently across the organization?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
