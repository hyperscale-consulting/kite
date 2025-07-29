from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class WorkloadDependencyUpdatesCheck:
    def __init__(self):
        self.check_id = "workload-dependency-updates"
        self.check_name = "Workload and Dependency Updates"

    @property
    def question(self) -> str:
        return (
            "Are mechanisms in place to quickly and safely update workloads and "
            "dependencies to latest available versions that provide known threat "
            "mitigations?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that mechanisms are in place to quickly and safely "
            "update workloads and dependencies to latest available versions that "
            "provide known threat mitigations."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Are teams automatically notified as soon as vulnerable components are "
            "detected?\n"
            "- Do teams have mechanisms (e.g. automated test suites) that can quickly "
            "provide confidence in updated workloads?\n"
            "- Do teams have automated processes for updating workloads?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
