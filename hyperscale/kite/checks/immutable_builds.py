from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class ImmutableBuildsCheck:
    def __init__(self):
        self.check_id = "immutable-builds"
        self.check_name = "Immutable Builds"

    @property
    def question(self) -> str:
        return (
            "Are builds immutable as they pass through the deployment pipeline, with "
            "environment specific configuration externalized?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that builds are immutable as they pass through the "
            "deployment pipeline."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Is the version of a workload that is tested the same version that is "
            "deployed?\n"
            "- Are all environment specific configurations externalized?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
