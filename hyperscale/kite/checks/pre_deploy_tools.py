from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class PreDeployToolsCheck:
    def __init__(self):
        self.check_id = "pre-deploy-tools"
        self.check_name = "Pre-deploy Incident Response Tools"

    @property
    def question(self) -> str:
        return (
            "Are tools required to support incident response deployed and configured "
            "in advance of an incident?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that essential incident response tools are deployed "
            "and configured before an incident occurs, rather than being deployed "
            "reactively."
        )

    def run(self) -> CheckResult:
        message = (
            "Are tools such as log analysis, forensic tools and dedicated accounts, "
            "break glass accounts and procedures, and monitoring systems deployed and "
            "configured in advance of an incident?\n"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
