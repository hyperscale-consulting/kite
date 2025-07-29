from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization
from hyperscale.kite.helpers import get_organization_structure_str


class IsolationBoundariesCheck:
    def __init__(self):
        self.check_id = "define-and-enforce-isolation-boundaries"
        self.check_name = "Define and Enforce Isolation Boundaries"

    @property
    def question(self) -> str:
        return (
            "Are data of different sensitivity levels properly isolated using "
            "accounts and SCPs?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that data of different sensitivity levels are "
            "properly isolated using accounts and Service Control Policies (SCPs)."
        )

    def run(self) -> CheckResult:
        org = get_organization()
        if org is None:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "AWS Organizations is not being used, so isolation boundaries "
                    "cannot be assessed."
                ),
            )
        org_structure = get_organization_structure_str(org)
        message = (
            "Consider the following factors for isolation boundaries:\n"
            "- Are data of different sensitivity levels (e.g., public, internal, "
            "confidential, restricted) stored in separate accounts?\n"
            "- Are Service Control Policies (SCPs) used to control which services and "
            "actions are allowed for each data sensitivity level?\n\n"
            "Organization Structure:\n"
            f"{org_structure}"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
