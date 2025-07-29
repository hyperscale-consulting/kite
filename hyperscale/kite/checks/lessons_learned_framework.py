from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class LessonsLearnedFrameworkCheck:
    def __init__(self):
        self.check_id = "lessons-learned-framework"
        self.check_name = "Lessons Learned Framework"

    @property
    def question(self) -> str:
        return (
            "Is a lessons learned framework in place to help prevent incidents from "
            "recurring and improve incident response?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that a lessons learned framework is in place to help "
            "prevent incidents from recurring and improve incident response."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Is there a formal process for capturing lessons learned after "
            "incidents?\n"
            "- Are root cause analyses conducted for security incidents?\n"
            "- Are lessons learned documented and shared with relevant teams?\n"
            "- Is there a process for implementing improvements based on lessons "
            "learned?\n"
            "- Are lessons learned incorporated into training and awareness programs?\n"
            "- Is there regular review and updating of incident response procedures "
            "based on lessons learned?\n"
            "- Are metrics tracked to measure the effectiveness of improvements?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
