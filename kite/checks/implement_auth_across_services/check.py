"""Check for implementing authentication across services."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "implement-auth-across-services"
CHECK_NAME = "Implement Authentication Across Services"


def check_implement_auth_across_services() -> Dict[str, Any]:
    """
    Check if appropriate authentication solutions have been implemented to authenticate
    and authorize traffic flows across the workload.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    # Define the message and prompts
    message = (
        "This check verifies that appropriate authentication solutions have been "
        "implemented to authenticate and authorize traffic flows across the "
        "workload.\n\n"
        "Consider the following factors:\n"
        "- Have appropriate authentication solutions been implemented? For example:\n"
        "  * mTLS\n"
        "  * VPC Lattice\n"
        "  * Service Connect\n"
        "  * IAM SigV4\n"
        "  * OAuth 2.0 or OIDC\n"
        "- Are the authentication mechanisms appropriate for the data sensitivity?"
    )
    prompt = (
        "Have appropriate authentication solutions been implemented to authenticate "
        "and authorize traffic flows across the workload?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Appropriate authentication solutions have been implemented to "
            "authenticate and authorize traffic flows across the workload."
        ),
        fail_message=(
            "Appropriate authentication solutions should be implemented to "
            "authenticate and authorize traffic flows across the workload."
        ),
        default=True,
    )

    return result


check_implement_auth_across_services._CHECK_ID = CHECK_ID
check_implement_auth_across_services._CHECK_NAME = CHECK_NAME
