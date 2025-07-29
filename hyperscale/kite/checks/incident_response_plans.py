from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class IncidentResponsePlansCheck:
    def __init__(self):
        self.check_id = "incident-response-plans"
        self.check_name = "Incident Response Plans"

    @property
    def question(self) -> str:
        return (
            "Is an incident response plan captured in a formal document covering the "
            "goals and function of the incident response team, stakeholder roles, "
            "communication plans, backup communication methods, incident response "
            "phases, and severity classification with escalation procedures?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that an incident response plan is captured in a "
            "formal document covering all required components."
        )

    def run(self) -> CheckResult:
        message = (
            "Does your incident response plan cover the following:\n"
            "- The goals and function of the incident response team\n"
            "- Incident response stakeholders and their roles when an incident occurs, "
            "including HR, Legal, Executive team, app owners, and developers\n"
            "- A communication plan\n"
            "- Backup communication methods\n"
            "- The phases of incident response and the high level actions to take in "
            "those phases\n"
            "- A process for classifying incident severity\n"
            "- Severity definitions and their impact on escalation procedures"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
