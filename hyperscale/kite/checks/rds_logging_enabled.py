from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import get_prowler_output


class RdsLoggingEnabledCheck:
    def __init__(self):
        self.check_id = "rds-logging-enabled"
        self.check_name = "RDS Logging Enabled"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return "This check verifies that RDS logging is enabled for all RDS instances."

    def run(self) -> CheckResult:
        prowler_results = get_prowler_output()
        check_id = "rds_instance_integration_cloudwatch_logs"
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
        message = (
            "All RDS instances have logging enabled."
            if passed
            else (
                f"Found {len(failing_resources)} RDS instances without logging enabled."
            )
        )
        details = {
            "message": message,
            "failing_resources": failing_resources,
        }
        return CheckResult(
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            reason=message,
            details=details,
        )
