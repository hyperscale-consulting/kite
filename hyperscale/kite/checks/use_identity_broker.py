from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class UseIdentityBrokerCheck:
    def __init__(self):
        self.check_id = "use-identity-broker"
        self.check_name = "Use Identity Broker for Temporary Privilege Escalation"

    @property
    def question(self) -> str:
        return (
            "Is an identity broker used to request and approve temporary "
            "elevated privileges for incident responders?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that an identity broker is used to request and "
            "approve temporary elevated privileges to responders in the event of "
            "an incident, as opposed to JIT provisioning or credential vaulting."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Is an identity broker used for temporary privilege escalation?\n"
            "- Is there a request and approval workflow for elevated privileges?\n"
            "- Are elevated privileges time-limited and automatically revoked?\n"
            "- Is there a clear process for requesting elevated access during "
            "incidents?\n"
            "- Are approvals documented and auditable?\n"
            "- Are elevated privileges limited to what is necessary for incident "
            "response?\n"
            "- Is there monitoring and alerting for elevated privilege usage?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
