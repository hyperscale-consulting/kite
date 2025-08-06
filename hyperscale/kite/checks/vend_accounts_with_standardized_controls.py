from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class VendAccountsWithStandardizedControlsCheck:
    def __init__(self):
        self.check_id = "vend-accounts-with-standardized-controls"
        self.check_name = "Vend Accounts with Standardized Controls"

    @property
    def question(self) -> str:
        return (
            "Are new accounts vended with standardized security controls already "
            "deployed?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that new accounts are vended with standardized "
            "security controls already deployed"
        )

    def run(self) -> CheckResult:
        message = (
            "For example, your standardized controls might include AWS Config rules "
            "with auto remediation configured, or buckets configured for securing log "
            "data. These controls can be deployed as part of the account vending "
            "process, for example by using Account Factory Customizations (AFC) or "
            "through a CI/CD pipeline that creates accounts and applies standardized "
            "controls via CloudFormation stacksets.\n\n"
            "Consider the following:\n"
            "- Are new accounts vended with standardized controls pre-deployed?\n"
            "- Are the controls in place before workloads are deployed?\n"
            "- Are mechanisms in place to update standardized controls across already "
            "provisioned accounts?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
