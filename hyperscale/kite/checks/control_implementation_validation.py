from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class ControlImplementationValidationCheck:
    def __init__(self):
        self.check_id = "control-implementation-validation"
        self.check_name = "Control Implementation Validation"

    @property
    def question(self) -> str:
        return (
            "Are security controls implemented and enforced through automation and "
            "policy and continually evaluated for their effectiveness?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that security controls are implemented and enforced "
            "through automation and policy and continually evaluated for their "
            "effectiveness in achieving objectives."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are SCPs, resource policies, role trust policies, and other "
            "guardrails used to prevent non-compliant resource configurations?\n"
            "- Are Security Hub standards and AWS Config conformance packs used to "
            "track conformance?\n"
            "- Is evidence of effectiveness at both a point in time and over a period "
            "of time readily reportable to auditors?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
