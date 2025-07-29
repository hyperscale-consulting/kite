from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class AvoidInteractiveAccessCheck:
    def __init__(self):
        self.check_id = "avoid-interactive-access"
        self.check_name = "Avoid Interactive Access"

    @property
    def question(self) -> str:
        return (
            "Are automated mechanisms such as Systems Manager automations, runbooks, "
            "and run commands used to automate and control activities performed on "
            "production environments rather than relying on interactive access?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that automated mechanisms are used instead of "
            "interactive access for production environments."
        )

    def run(self) -> CheckResult:
        message = (
            "- Are Systems Manager automations used for routine tasks?\n"
            "- Are Systems Manager runbooks used for complex operations?\n"
            "- Are Systems Manager run commands used for ad-hoc tasks?\n"
            "- Are IAM policies used to define who can perform these actions and "
            "the conditions under which they are permitted?\n"
            "- Are all administrative tasks automated where possible?\n"
            "- Are these automations tested thoroughly in non-production environments?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
