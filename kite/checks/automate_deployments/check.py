"""Check for fully automated deployments."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "automate-deployments"
CHECK_NAME = "Automated Deployments"


def check_automate_deployments() -> dict[str, Any]:
    """
    Check if deployments are fully automated, removing all need for persistent human
    access to production environments.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that deployments are fully automated, removing all need "
        "for persistent human access to production environments.\n\n"
        "Consider the following factors:\n"
        "- Are all deployments fully automated through CI/CD pipelines?\n"
        "- Is there no persistent human access required to production environments?"
    )
    prompt = (
        "Are deployments fully automated, removing all need for persistent human "
        "access to production environments?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Deployments are fully automated, removing all need for persistent human "
            "access to production environments."
        ),
        fail_message=(
            "Deployments should be fully automated, removing all need for persistent "
            "human access to production environments."
        ),
        default=True,
    )


check_automate_deployments._CHECK_ID = CHECK_ID
check_automate_deployments._CHECK_NAME = CHECK_NAME
