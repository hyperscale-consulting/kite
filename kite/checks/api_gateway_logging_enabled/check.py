"""Check for enabled API Gateway logging."""

from typing import Dict, Any, List

from kite.helpers import get_prowler_output


CHECK_ID = "api-gateway-logging-enabled"
CHECK_NAME = "API Gateway Logging Enabled"


def check_api_gateway_logging_enabled() -> Dict[str, Any]:
    """
    Check if API Gateway logging is enabled.

    This check verifies that API Gateway logging is enabled by checking Prowler
    results for the following check IDs:
    - apigateway_restapi_logging_enabled
    - apigatewayv2_api_access_logging_enabled

    Both checks must pass for this check to pass.

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
        "apigateway_restapi_logging_enabled",
        "apigatewayv2_api_access_logging_enabled",
    ]

    # Track failing resources
    failing_resources: List[Dict[str, Any]] = []

    # Check results for each check ID
    for check_id in check_ids:
        if check_id in prowler_results:
            # Get results for this check ID
            results = prowler_results[check_id]

            # Add failing resources to the list
            for result in results:
                if result.status != "PASS":
                    failing_resources.append({
                        "account_id": result.account_id,
                        "resource_uid": result.resource_uid,
                        "resource_name": result.resource_name,
                        "resource_details": result.resource_details,
                        "region": result.region,
                        "status": result.status,
                        "check_id": check_id
                    })

    # Determine if the check passed
    passed = len(failing_resources) == 0

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS" if passed else "FAIL",
        "details": {
            "message": (
                "All API Gateway APIs have logging enabled."
                if passed
                else (
                    f"Found {len(failing_resources)} API Gateway APIs "
                    "without logging enabled."
                )
            ),
            "failing_resources": failing_resources,
        },
    }


# Attach the check ID and name to the function
check_api_gateway_logging_enabled._CHECK_ID = CHECK_ID
check_api_gateway_logging_enabled._CHECK_NAME = CHECK_NAME
