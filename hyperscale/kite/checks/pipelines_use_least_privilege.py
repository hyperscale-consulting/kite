from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class PipelinesUseLeastPrivilegeCheck:
    def __init__(self):
        self.check_id = "pipelines-use-least-privilege"
        self.check_name = "Pipeline Least Privilege"

    @property
    def question(self) -> str:
        return (
            "Are roles used by CI/CD pipelines assigned only the privileges needed to "
            "deploy their workloads?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that roles used by CI/CD pipelines are assigned only "
            "the privileges needed to deploy their workloads."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are pipeline roles scoped to only the required services and actions?\n"
            "- Are pipeline roles restricted to only the resources they need to manage?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
