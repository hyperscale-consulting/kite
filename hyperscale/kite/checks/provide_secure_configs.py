from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class ProvideSecureConfigurationsCheck:
    def __init__(self):
        self.check_id = "provide-secure-configurations"
        self.check_name = "Provide Secure Configurations"

    @property
    def question(self) -> str:
        return (
            "Are secure, standardized, service configurations made available for "
            "workload teams to deploy via a self-serve mechanism?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that workload teams are provided with secure, "
            "standardized service configurations are via self-serve mechanisms."
        )

    def run(self) -> CheckResult:
        context = (
            "IaC can be used to define standardized service configurations which are "
            "secure-by-design, and can then be shared with workload teams via "
            "self-service mechanisms such as Service Catalog."
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
