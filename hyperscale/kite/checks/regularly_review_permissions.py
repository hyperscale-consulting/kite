from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class RegularlyReviewPermissionsCheck:
    def __init__(self):
        self.check_id = "regularly-review-permissions"
        self.check_name = "Regularly Review Permissions"

    @property
    def question(self) -> str:
        return (
            "Are permissions reviewed regularly and unused permissions, identities, "
            "and policies removed?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that permissions are reviewed regularly and unused "
            "permissions, identities, and policies are removed."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are permissions reviewed on a regular schedule (e.g., quarterly)?\n"
            "- Are unused users, roles, and groups removed?\n"
            "- Are unused policies (both inline and managed) removed?\n"
            "- Are unused permissions removed from policies?\n"
            "- Is there a documented process for permission reviews?\n"
            "- Are permission reviews tracked and documented?\n"
            "- Are findings from permission reviews acted upon?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
