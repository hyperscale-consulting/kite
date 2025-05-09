"""Check for use of Service Catalog or similar for approved service configurations."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "service-catalog"
CHECK_NAME = "Service Catalog"


def check_service_catalog() -> Dict[str, Any]:
    """
    Check if Service Catalog or similar is used to allow teams to deploy approved
    service configurations.


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
        "This check verifies that Service Catalog or similar is used to allow teams "
        "to deploy approved service configurations.\n\n"
        "Consider the following factors:\n"
        "- Is Service Catalog or similar used for approved service configurations?\n"
        "- Can teams deploy approved service configurations?\n"
        "- Are the service configurations regularly reviewed and updated?"
    )
    prompt = (
        "Is Service Catalog or similar used to allow teams to deploy approved "
        "service configurations?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Service Catalog or similar is used to allow teams to deploy approved "
            "service configurations."
        ),
        fail_message=(
            "Service Catalog or similar should be used to allow teams to deploy "
            "approved service configurations."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_service_catalog._CHECK_ID = CHECK_ID
check_service_catalog._CHECK_NAME = CHECK_NAME
