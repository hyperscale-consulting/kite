"""Check for secure SSL cipher usage across AWS services."""

from typing import Dict, Any, List

from kite.helpers import get_prowler_output


CHECK_ID = "avoid-insecure-ssl-ciphers"
CHECK_NAME = "Avoid Insecure SSL Ciphers"


def check_avoid_insecure_ssl_ciphers() -> Dict[str, Any]:
    """
    Check if secure SSL ciphers are used across AWS services.

    This check verifies that secure SSL ciphers are used by checking Prowler
    results for the following check IDs:
    - cloudfront_distributions_using_deprecated_ssl_protocols
    - elb_insecure_ssl_ciphers
    - elbv2_insecure_ssl_ciphers

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
        "cloudfront_distributions_using_deprecated_ssl_protocols",
        "elb_insecure_ssl_ciphers",
        "elbv2_insecure_ssl_ciphers",
    ]

    # Track failing resources by service
    failing_resources: Dict[str, List[Dict[str, Any]]] = {}

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
                    elif service_name == "CLOUDFRONT":
                        service_name = "CloudFront Distribution"

                    if service_name not in failing_resources:
                        failing_resources[service_name] = []

                    failing_resources[service_name].append({
                        "account_id": result.account_id,
                        "resource_uid": result.resource_uid,
                        "resource_name": result.resource_name,
                        "resource_details": result.resource_details,
                        "region": result.region,
                        "status": result.status,
                        "check_id": check_id
                    })

    # Build the message
    message = (
        "This check verifies that secure SSL ciphers are used across AWS services.\n\n"
    )

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
check_avoid_insecure_ssl_ciphers._CHECK_ID = CHECK_ID
check_avoid_insecure_ssl_ciphers._CHECK_NAME = CHECK_NAME
