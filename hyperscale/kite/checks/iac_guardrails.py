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
            "IaC before deployment?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that guardrails are in place to detect and alert "
            "on misconfigurations in IaC before deployment."
        )

    def run(self) -> CheckResult:
        message = (
            "Tools such as cfn-nag and Clouformation Guard can provide IaC guardrails "
            "by detecting misconfigurations in IaC and then alerting and preventing "
            "deployment of non-compliant resources."
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
