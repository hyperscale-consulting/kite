from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class CaptureKeyContactsCheck:
    def __init__(self):
        self.check_id = "capture-key-contacts"
        self.check_name = "Capture Key Contacts"

    @property
    def question(self) -> str:
        return (
            "Are the contact details of key personnel and external resources "
            "captured and documented so that the right people can be involved "
            "in responding to a security event?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that the contact details of key personnel and "
            "external resources are captured and documented so that the right "
            "people can be involved in responding to a security event."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are contact details for key personnel documented?\n"
            "- Are contact details for external partners documented?\n"
            "- Is there a process for keeping contact information up to date?\n"
            "- Are contact details accessible during a security incident?\n"
            "- Are roles and responsibilities for contacts defined?\n"
            "- Are there a clear escalation paths?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
