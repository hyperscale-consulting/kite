from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class SensitivityControlsCheck:
    def __init__(self):
        self.check_id = "controls-implemented-based-on-sensitivity"
        self.check_name = "Controls implemented based on data sensitivity"

    @property
    def question(self) -> str:
        return (
            "Are appropriate controls implemented based on data sensitivity levels "
            "as required by your data classification policy?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that appropriate controls are implemented based on "
            "data sensitivity levels."
        )

    def run(self) -> CheckResult:
        context = (
            "This check verifies that appropriate controls are implemented based on "
            "data sensitivity levels.\n\n"
            "Consider the following:\n"
            "- Are access controls (IAM policies, SCPs) implemented based on data "
            "sensitivity?\n"
            "- Is encryption (at rest and in transit) implemented according to data "
            "sensitivity requirements?\n"
            "- Are audit logs and monitoring configured appropriately for each "
            "sensitivity level?\n"
            "- Are data retention policies implemented based on sensitivity?\n"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
