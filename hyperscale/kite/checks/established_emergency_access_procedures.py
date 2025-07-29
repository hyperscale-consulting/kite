from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class EstablishedEmergencyAccessProceduresCheck:
    def __init__(self):
        self.check_id = "established-emergency-access-procedures"
        self.check_name = "Establish emergency access procedures"

    @property
    def question(self) -> str:
        return "Are emergency access procedures properly established?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that emergency access procedures are properly "
            "established and documented."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are there well documented emergency procedures covering - at a minimum "
            "- the 3 primary failure modes (IdP failure, IdP misconfiguration, "
            "Identity Center failure)?\n"
            "- Do processes have pre-conditions and assumptions documented explaining "
            "when the process should be used and when it should not be used, for each "
            "failure mode?\n"
            "- Is there a dedicated AWS account that is used for emergency access?\n"
            "- Are there dedicated IAM accounts, protected by strong passwords and "
            "MFA, for each emergency incident responder?\n"
            "- Are all resources required by the emergency access processes "
            "pre-created?\n"
            "- Are emergency access processes included in incident management plans?\n"
            "- Can the emergency access process only be initiated by authorized "
            "users?\n"
            "- Does the emergency access process require approval from peers / "
            "management\n"
            "- Is robust logging, monitoring and alerting in place for the emergency "
            "access process and mechanisms?\n"
            "- Are emergency access processes tested periodically?\n"
            "- Are emergency access mechanisms disabled during normal operation?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
