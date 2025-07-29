from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class AutomateForensicsCheck:
    def __init__(self):
        self.check_id = "automate-forensics"
        self.check_name = "Automate Forensics"

    @property
    def question(self) -> str:
        return (
            "Is the collection of forensics, such as snapshots of EBS volumes, "
            "memory dumps, process lists and logs automated?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that the collection of forensics, such as snapshots "
            "of EBS volumes, memory dumps, process lists and logs is automated as far "
            "as possible."
        )

    def run(self) -> CheckResult:
        message = (
            "This check verifies that the collection of forensics, such as snapshots "
            "of EBS volumes, memory dumps, process lists and logs is automated as far "
            "as possible."
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
