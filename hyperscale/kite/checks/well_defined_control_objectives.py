from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class WellDefinedControlObjectivesCheck:
    def __init__(self):
        self.check_id = "well-defined-control-objectives"
        self.check_name = "Well-Defined Control Objectives"

    @property
    def question(self) -> str:
        return (
            "Are security control objectives well-defined and aligned with compliance "
            "requirements?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that security control objectives are well-defined and "
            "aligned with compliance requirements."
        )

    def run(self) -> CheckResult:
        context = (
            "Things to consider:\n"
            "- Are security control objectives documented?\n"
            "- Is a cybersecurity framework, such as NIST CSF, CIS, ISO 27001, Cyber "
            "Essentials etc. used as a basis for control objectives?\n"
            "- Are compliance requirements well understood - e.g. GDPR, PCI DSS, "
            "market expectations, etc. And are these aligned to the control "
            "objectives?\n"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
