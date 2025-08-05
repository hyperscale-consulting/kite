from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization
from hyperscale.kite.helpers import get_organization_structure_str


class OuStructureCheck:
    def __init__(self):
        self.check_id = "ou-structure"
        self.check_name = "OU Structure"

    @property
    def question(self) -> str:
        return "Is there an effective OU structure?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that there is an effective OU structure in the "
            "organization."
        )

    def run(self) -> CheckResult:
        org = get_organization()
        if org is None:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "AWS Organizations is not being used, so OU structure "
                    "cannot be assessed."
                ),
            )
        org_structure = get_organization_structure_str(org)
        message = (
            "A well-designed Organizational Unit (OU) structure can make it easier to "
            "apply security controls across accounts. Therefore, your OU structure "
            "should be aligned with business needs, data sensitivity and workload "
            "structure to enable grouping of accounts based on function, compliance "
            "requirements, data sensitivity, or a common set of controls.\n\n"
            "A well-designed OU structure is likely to include:\n"
            "- A Security OU\n"
            "- A Workloads OU\n"
            "- Separate prod and non-prod sub-OUs\n"
            "- Other OUs, such as Infrastructure, Sandbox, Deployments, as required\n\n"
            "Organization Structure:\n"
            f"{org_structure}"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
