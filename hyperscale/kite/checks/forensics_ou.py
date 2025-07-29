from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization
from hyperscale.kite.helpers import get_organization_structure_str


class ForensicsOuCheck:
    def __init__(self):
        self.check_id = "forensics-ou"
        self.check_name = "Forensics OU"

    @property
    def question(self) -> str:
        return (
            "Is there a forensic OU with one or more accounts dedicated to "
            "capturing forensics for analysis in the event of a security incident?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that there is a forensic OU with one or more "
            "accounts dedicated to capturing forensics for analysis in the event "
            "of a security incident."
        )

    def run(self) -> CheckResult:
        org = get_organization()
        if org is None:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "AWS Organizations is not being used, so forensic OU "
                    "structure cannot be assessed."
                ),
            )
        org_structure = get_organization_structure_str(org)
        message = (
            "Consider the following factors:\n"
            "- Is there a dedicated OU for forensic activities?\n"
            "- Does the forensic OU contain one or more dedicated accounts?\n"
            "- Are these accounts used specifically for capturing forensics?\n"
            "Organization Structure:\n"
            f"{org_structure}"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
