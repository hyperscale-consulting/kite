from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class ThreatModelPipelinesCheck:
    def __init__(self):
        self.check_id = "threat-model-pipelines"
        self.check_name = "Pipeline Threat Modeling"

    @property
    def question(self) -> str:
        return (
            "Are CI/CD pipelines threat modeled in the same way as other production "
            "workloads to identify and address risks to the software supply chain?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that CI/CD pipelines are threat modeled in the same "
            "way as other production workloads to identify and address risks to the "
            "software supply chain."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Are CI/CD pipelines included in threat modeling exercises?\n"
            "- Are software supply chain risks identified and addressed?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
