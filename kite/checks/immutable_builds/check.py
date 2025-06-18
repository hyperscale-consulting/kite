"""Check for immutable builds."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "immutable-builds"
CHECK_NAME = "Immutable Builds"


def check_immutable_builds() -> Dict[str, Any]:
    """
    Check if builds are immutable as they pass through the deployment pipeline.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that builds are immutable as they pass through the "
        "deployment pipeline.\n\n"
        "Consider the following factors:\n"
        "- Is the version of a workload that is tested the same version that is "
        "deployed?\n"
        "- Are all environment specific configurations externalized?"
    )
    prompt = (
        "Are builds immutable as they pass through the deployment pipeline, with "
        "environment specific configuration externalized?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Builds are immutable as they pass through the deployment pipeline, with "
            "environment specific configuration externalized."
        ),
        fail_message=(
            "Builds should be immutable as they pass through the deployment pipeline, "
            "with environment specific configuration externalized."
        ),
        default=True,
    )


check_immutable_builds._CHECK_ID = CHECK_ID
check_immutable_builds._CHECK_NAME = CHECK_NAME
