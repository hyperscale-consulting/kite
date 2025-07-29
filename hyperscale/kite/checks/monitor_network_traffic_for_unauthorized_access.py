from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class MonitorNetworkTrafficForUnauthorizedAccessCheck:
    def __init__(self):
        self.check_id = "monitor-network-traffic-for-unauthorized-access"
        self.check_name = "Monitor Network Traffic for Unauthorized Access"

    @property
    def question(self) -> str:
        return (
            "Is network traffic continually monitored for unintended communication "
            "channels, unauthorized principals attempting to access protected "
            "resources, and other improper access patterns?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that network traffic is continually monitored for "
            "unintended communication channels, unauthorized principals attempting to "
            "access protected resources, and other improper access patterns."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Is network traffic monitored for unexpected or unauthorized "
            "communication channels?\n"
            "- Are there controls in place to detect unauthorized principals "
            "attempting to access protected resources?\n"
            "- Are improper or suspicious access patterns detected and investigated?\n"
            "- Are alerts generated and responded to in a timely manner?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
