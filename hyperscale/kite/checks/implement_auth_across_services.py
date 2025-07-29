from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class ImplementAuthAcrossServicesCheck:
    def __init__(self):
        self.check_id = "implement-auth-across-services"
        self.check_name = "Implement Authentication Across Services"

    @property
    def question(self) -> str:
        return (
            "Have appropriate authentication solutions been implemented to "
            "authenticate and authorize traffic flows across the workload?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that appropriate authentication solutions have been "
            "implemented to authenticate and authorize traffic flows across the "
            "workload."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Have appropriate authentication solutions been implemented? For "
            "example:\n"
            "  * mTLS\n"
            "  * VPC Lattice\n"
            "  * Service Connect\n"
            "  * IAM SigV4\n"
            "  * OAuth 2.0 or OIDC\n"
            "- Are the authentication mechanisms appropriate for the data sensitivity?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
