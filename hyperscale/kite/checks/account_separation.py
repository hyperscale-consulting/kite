from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization
from hyperscale.kite.helpers import get_organization_structure_str


class AccountSeparationCheck:
    def __init__(self):
        self.check_id = "account-separation"
        self.check_name = "Account Separation"

    @property
    def question(self) -> str:
        return "Is there effective account separation in the organization?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that unrelated workloads, or workloads with different "
            "data sensitivity, are separated into different accounts. It also checks "
            "for separation of dev, test, tooling, deployment, log archive, and audit "
            "accounts."
        )

    def run(self) -> CheckResult:
        org = get_organization()
        if org is None:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="AWS Organizations is not being used, so account separation "
                "cannot be used.",
            )
        org_structure = get_organization_structure_str(org)
        message = (
            "Consider the following factors for account separation:\n"
            "- Are unrelated workloads, or workloads with different data sensitivity, "
            "separated into different accounts?\n"
            "- Are dev, test, dev tooling, deployment, etc accounts separated from "
            "workload accounts?\n"
            "- Are there separate log archive and audit (AKA security tooling) "
            "accounts?\n\n"
            "Organization Structure:\n"
            f"{org_structure}"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
