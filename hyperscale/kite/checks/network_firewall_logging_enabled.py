from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import get_prowler_output


class NetworkFirewallLoggingEnabledCheck:
    def __init__(self):
        self.check_id = "network-firewall-logging-enabled"
        self.check_name = "Network Firewall Logging Enabled"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return "This check verifies that network firewall logging is enabled."

    def run(self) -> CheckResult:
        prowler_results = get_prowler_output()
        check_id = "networkfirewall_logging_enabled"
        failing_resources = []
        if check_id in prowler_results:
            results = prowler_results[check_id]
            for result in results:
                if result.status != "PASS":
                    failing_resources.append(
                        {
                            "account_id": result.account_id,
                            "resource_uid": result.resource_uid,
                            "resource_name": result.resource_name,
                            "resource_details": result.resource_details,
                            "region": result.region,
                            "status": result.status,
                        }
                    )
        passed = len(failing_resources) == 0
        return CheckResult(
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            reason=(
                "All network firewalls have logging enabled."
                if passed
                else (
                    f"Found {len(failing_resources)} network firewalls without "
                    "logging enabled."
                )
            ),
            details={
                "failing_resources": failing_resources,
            },
        )
