"""Check for HTTPS enforcement across AWS services."""

from typing import Any

from kite.helpers import get_prowler_output

CHECK_ID = "enforce-https"
CHECK_NAME = "Enforce HTTPS"


def check_enforce_https() -> dict[str, Any]:
    """
    Check if HTTPS is enforced across AWS services.

    This check verifies that HTTPS is enforced by checking Prowler results for the
    following check IDs:
    - opensearch_service_domains_node_to_node_encryption_enabled
    - opensearch_service_domains_https_communications_enforced
    - apigateway_restapi_client_certificate_enabled
    - cloudfront_distributions_https_enabled
    - elb_ssl_listeners
    - elbv2_ssl_listeners
    - s3_bucket_secure_transport_policy

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - failing_resources: List of resources that failed the check
    """
    # Get Prowler results
    prowler_results = get_prowler_output()

    # The check IDs we're interested in
    check_ids = [
        "opensearch_service_domains_node_to_node_encryption_enabled",
        "opensearch_service_domains_https_communications_enforced",
        "apigateway_restapi_client_certificate_enabled",
        "cloudfront_distributions_https_enabled",
        "elb_ssl_listeners",
        "elbv2_ssl_listeners",
        "s3_bucket_secure_transport_policy",
    ]

    # Track failing resources by service
    failing_resources: dict[str, list[dict[str, Any]]] = {}

    # Check results for each check ID
    for check_id in check_ids:
        if check_id in prowler_results:
            # Get results for this check ID
            results = prowler_results[check_id]

            # Add failing resources to the list
            for result in results:
                if result.status != "PASS":
                    # Determine the service name from the check ID
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

    # Build the message
    message = "This check verifies that HTTPS is enforced across AWS services.\n\n"

    if failing_resources:
        message += "The following resources do not have HTTPS enforced:\n\n"
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
        message += "All services have HTTPS enforced.\n"

    # Determine if the check passed
    passed = len(failing_resources) == 0

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS" if passed else "FAIL",
        "details": {
            "message": message,
            "failing_resources": failing_resources,
        },
    }


# Attach the check ID and name to the function
check_enforce_https._CHECK_ID = CHECK_ID
check_enforce_https._CHECK_NAME = CHECK_NAME
