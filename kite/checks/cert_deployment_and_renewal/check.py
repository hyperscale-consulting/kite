"""Check for automated certificate deployment and renewal."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "automate-cert-deployment-and-renewal"
CHECK_NAME = "Automate Certificate Deployment and Renewal"


def check_cert_deployment_and_renewal() -> Dict[str, Any]:
    """
    Check if certificate deployment and renewal is automated.

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
        "This check verifies that certificate deployment and renewal is automated for "
        "public and private certificates.\n"
    )
    prompt = (
        "Is certificate deployment and renewal automated?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Certificate deployment and renewal is automated."
        ),
        fail_message=(
            "Certificate deployment and renewal should be automated."
        ),
        default=True,
    )

    return result


check_cert_deployment_and_renewal._CHECK_ID = CHECK_ID
check_cert_deployment_and_renewal._CHECK_NAME = CHECK_NAME
