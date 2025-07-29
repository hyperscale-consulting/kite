from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class AccessManagementLifecycleCheck:
    def __init__(self):
        self.check_id = "access-management-lifecycle-defined"
        self.check_name = (
            "Access Management Lifecycle Process is Defined and Documented"
        )

    @property
    def question(self) -> str:
        return (
            "Is there a defined and documented process for managing user access "
            "throughout the user lifecycle?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that there is a defined and documented process for "
            "managing user access throughout the user lifecycle, including granting "
            "initial access, periodic access reviews, and offboarding."
        )

    def run(self) -> CheckResult:
        message = (
            "Please consider the following:\n\n"
            "- Is the access management lifecycle process clearly defined and "
            "documented?\n"
            "- Does it include procedures for granting initial access?\n"
            "- Does it include procedures for periodic access reviews?\n"
            "- Does it include procedures for offboarding?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
