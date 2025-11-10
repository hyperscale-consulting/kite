from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import get_prowler_output


class EnforceHttpsCheck:
    def __init__(self):
        self.check_id = "enforce-https"
        self.check_name = "Enforce HTTPS"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return "This check verifies that HTTPS is enforced across AWS services."

    def run(self) -> CheckResult:
        prowler_results = get_prowler_output()
        check_ids = [
            "opensearch_service_domains_node_to_node_encryption_enabled",
            "opensearch_service_domains_https_communications_enforced",
            "apigateway_restapi_client_certificate_enabled",
            "cloudfront_distributions_https_enabled",
            "elb_ssl_listeners",
            "elbv2_ssl_listeners",
            "s3_bucket_secure_transport_policy",
        ]
        failing_resources = {}
        for check_id in check_ids:
            if check_id in prowler_results:
                results = prowler_results[check_id]
                for result in results:
                    if result.status != "PASS":
                        service_name = check_id.split("_")[0].upper()
                        if service_name == "ELB":
                            service_name = "Classic Load Balancer"
                        elif service_name == "ELBV2":
                            service_name = "Application Load Balancer"
                        elif service_name == "S3":
                            service_name = "S3 Bucket"
                        elif service_name == "APIGATEWAY":
                            service_name = "API Gateway"
                        elif service_name == "OPENSEARCH":
                            service_name = "OpenSearch"
                        if service_name not in failing_resources:
                            failing_resources[service_name] = []
                        failing_resources[service_name].append(
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
        if failing_resources:
            reason = f"{len(failing_resources)} resources do not have HTTPS enforced"
        else:
            reason = "All services have HTTPS enforced."
        passed = len(failing_resources) == 0
        return CheckResult(
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            reason=reason,
            details={
                "failing_resources": failing_resources,
            },
        )

    @property
    def criticality(self) -> int:
        return 7

    @property
    def difficulty(self) -> int:
        return 2
