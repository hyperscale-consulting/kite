"""Check for IaC templates stored in version control with CI/CD testing."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "iac-version-control"
CHECK_NAME = "IaC Version Control"


def check_iac_version_control() -> dict[str, Any]:
    """
    Check if IaC templates are stored in version control, tested as part of a CI/CD
    pipeline and automatically deployed to production.

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
        "This check verifies that IaC templates are stored in version control, "
        "tested as part of a CI/CD pipeline and automatically deployed to "
        "production.\n\n"
        "Consider the following factors:\n"
        "- Are IaC templates stored in version control?\n"
        "- Are IaC templates tested as part of a CI/CD pipeline?\n"
        "- Are IaC templates automatically deployed to production?"
    )
    prompt = (
        "Are IaC templates stored in version control, tested as part of a CI/CD "
        "pipeline and automatically deployed to production?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "IaC templates are stored in version control, tested as part of a CI/CD "
            "pipeline and automatically deployed to production."
        ),
        fail_message=(
            "IaC templates should be stored in version control, tested as part of a "
            "CI/CD pipeline and automatically deployed to production."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_iac_version_control._CHECK_ID = CHECK_ID
check_iac_version_control._CHECK_NAME = CHECK_NAME
