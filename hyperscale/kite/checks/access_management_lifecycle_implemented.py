from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class AccessManagementLifecycleImplementedCheck:
    def __init__(self):
        self.check_id = "access-management-lifecycle-implemented"
        self.check_name = (
            "Access Management Lifecycle Process is Effectively Implemented"
        )

    @property
    def question(self) -> str:
        return (
            "Is the access management lifecycle process effectively implemented "
            "and followed?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that regular access reviews are being conducted, "
            "access revocation is prompt and effective, and there is a process for "
            "continuous improvement."
        )

    def run(self) -> CheckResult:
        message = (
            "Please consider the following:\n\n"
            "- Are regular access reviews being conducted as scheduled?\n"
            "- Is access revoked promptly when no longer needed?\n"
            "- Is there a process to identify and implement improvements?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
