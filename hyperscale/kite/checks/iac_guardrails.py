from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class IacGuardrailsCheck:
    def __init__(self):
        self.check_id = "iac-guardrails"
        self.check_name = "IaC Guardrails"

    @property
    def question(self) -> str:
        return (
            "Are guardrails in place to detect and alert on misconfigurations in "
            "templates before deployment (e.g. CloudFormation Guard, cfn-lint, "
            "cfn-nag, CloudFormation Hooks etc)?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that guardrails are in place to detect and alert "
            "on misconfigurations in templates before deployment."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are guardrails in place to detect misconfigurations?\n"
            "- Are guardrails in place to alert on misconfigurations?\n"
            "- Are guardrails used before deployment?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
