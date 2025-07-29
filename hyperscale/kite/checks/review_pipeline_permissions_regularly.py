from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class ReviewPipelinePermissionsRegularlyCheck:
    def __init__(self):
        self.check_id = "review-pipeline-permissions-regularly"
        self.check_name = "Regular Pipeline Permissions Review"

    @property
    def question(self) -> str:
        return "Are permissions granted to CI/CD pipeline roles reviewed regularly?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that permissions granted to CI/CD pipeline roles are "
            "reviewed regularly to ensure they follow the principle of least privilege."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Are pipeline role permissions reviewed on a regular schedule?\n"
            "- Are unused permissions identified and removed?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
