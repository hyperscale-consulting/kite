from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class SecurityIrPlaybooksCheck:
    def __init__(self):
        self.check_id = "security-ir-playbooks"
        self.check_name = "Security Incident Response Playbooks"

    @property
    def question(self) -> str:
        return (
            "Are security incident response playbooks in place for anticipated "
            "incidents such as DoS, ransomware, or credential compromise, "
            "including prerequisites, roles, response steps, and expected outcomes?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that security incident response playbooks are in "
            "place for anticipated incidents such as DoS, ransomware, or credential "
            "compromise."
        )

    def run(self) -> CheckResult:
        context = (
            "This check verifies that security incident response playbooks are in "
            "place for anticipated incidents such as DoS, ransomware, or credential "
            "compromise.\n\n"
            "Consider the following factors:\n"
            "- Are playbooks available for common incident types (DoS, ransomware, "
            "credential compromise, data breach, malware)?\n"
            "- Do playbooks include prerequisites and dependencies?\n"
            "- Do playbooks clearly define who needs to be involved and their roles?\n"
            "- Do playbooks include step-by-step response procedures?\n"
            "- Do playbooks define expected outcomes and success criteria?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
