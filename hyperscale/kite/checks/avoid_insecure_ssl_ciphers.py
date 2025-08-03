from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import get_prowler_output


class AvoidInsecureSslCiphersCheck:
    def __init__(self):
        self.check_id = "avoid-insecure-ssl-ciphers"
        self.check_name = "Avoid Insecure SSL Ciphers"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that secure SSL ciphers are used across CloudFront, "
            "Classic Load Balancer, and Application Load Balancer."
        )

    def run(self) -> CheckResult:
        prowler_results = get_prowler_output()
        check_ids = [
            "cloudfront_distributions_using_deprecated_ssl_protocols",
            "elb_insecure_ssl_ciphers",
            "elbv2_insecure_ssl_ciphers",
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
                        elif service_name == "CLOUDFRONT":
                            service_name = "CloudFront Distribution"
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
        message = ""
        if failing_resources:
            message += "The following resources are using insecure SSL ciphers:\n\n"
            for service, resources in sorted(failing_resources.items()):
                message += f"{service}:\n"
                for resource in sorted(resources, key=lambda x: x["resource_name"]):
                    message += (
                        f"  - {resource['resource_name']} "
                        f"(Account: {resource['account_id']}, "
                        f"Region: {resource['region']})\n"
                    )
                message += "\n"
        else:
            message += "All services are using secure SSL ciphers.\n"
        passed = len(failing_resources) == 0
        return CheckResult(
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            reason=message,
            details={
                "failing_resources": failing_resources,
            },
        )
