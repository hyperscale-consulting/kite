from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class DefineAndDocumentWorkloadNetworkFlowsCheck:
    def __init__(self):
        self.check_id = "define-and-document-workload-network-flows"
        self.check_name = "Define and Document Workload Network Flows"

    @property
    def question(self) -> str:
        return (
            "Have workload network flows been defined and documented in a data flow "
            "diagram?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that workload network flows have been defined and "
            "documented in a data flow diagram."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are all network flows between components clearly defined?\n"
            "- Are data flow diagrams up to date and maintained?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
