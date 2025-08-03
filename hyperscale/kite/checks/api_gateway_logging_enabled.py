from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import get_prowler_output


class ApiGatewayLoggingEnabledCheck:
    def __init__(self):
        self.check_id = "api-gateway-logging-enabled"
        self.check_name = "API Gateway Logging Enabled"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return "This check verifies that API Gateway logging is enabled."

    def run(self) -> CheckResult:
        prowler_results = get_prowler_output()
        check_ids = [
            "apigateway_restapi_logging_enabled",
            "apigatewayv2_api_access_logging_enabled",
        ]
        failing_resources = []
        for check_id in check_ids:
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
                                "check_id": check_id,
                            }
                        )
        passed = len(failing_resources) == 0
        message = (
            "All API Gateway APIs have logging enabled."
            if passed
            else (
                f"Found {len(failing_resources)} API Gateway APIs "
                "without logging enabled."
            )
        )
        return CheckResult(
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            reason=message,
            details={
                "failing_resources": failing_resources,
            },
        )
