from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class ThreatIntelligenceMonitoringCheck:
    def __init__(self):
        self.check_id = "threat-intelligence-monitoring"
        self.check_name = "Threat Intelligence Monitoring"

    @property
    def question(self) -> str:
        return (
            "Do teams have a reliable and repeatable mechanism to stay informed of "
            "the latest threat intelligence?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that teams have a reliable and repeatable mechanism "
            "to stay informed of the latest threat intelligence."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Do teams regularly review the MITRE ATTACK knowledge base?\n"
            "- Are teams monitoring MITRE's CVE list for relevant vulnerabilities?\n"
            "- Do teams stay updated with the OWASP top 10 lists?\n"
            "- Do teams subscribe to and review security blogs and bulletins "
            "(e.g., AWS Security Bulletins)?\n"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
