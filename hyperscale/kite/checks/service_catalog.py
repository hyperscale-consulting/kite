from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class ServiceCatalogCheck:
    def __init__(self):
        self.check_id = "service-catalog"
        self.check_name = "Service Catalog"

    @property
    def question(self) -> str:
        return (
            "Is Service Catalog or similar used to allow teams to deploy approved "
            "service configurations?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that Service Catalog or similar is used to allow "
            "teams to deploy approved service configurations."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Is Service Catalog or similar used for approved service "
            "configurations?\n"
            "- Can teams deploy approved service configurations?\n"
            "- Are the service configurations regularly reviewed and updated?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
