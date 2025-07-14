"""Check for CI/CD pipeline least privilege."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "pipelines-use-least-privilege"
CHECK_NAME = "Pipeline Least Privilege"


def check_pipelines_use_least_privilege() -> dict[str, Any]:
    """
    Check if roles used by CI/CD pipelines are assigned only the privileges needed
    to deploy their workloads.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that roles used by CI/CD pipelines are assigned only "
        "the privileges needed to deploy their workloads.\n\n"
        "Consider the following factors:\n"
        "- Are pipeline roles scoped to only the required services and actions?\n"
        "- Are pipeline roles restricted to only the resources they need to manage?"
    )
    prompt = (
        "Are roles used by CI/CD pipelines assigned only the privileges needed to "
        "deploy their workloads?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Roles used by CI/CD pipelines are assigned only the privileges needed "
            "to deploy their workloads."
        ),
        fail_message=(
            "Roles used by CI/CD pipelines should be assigned only the privileges "
            "needed to deploy their workloads."
        ),
        default=True,
    )


check_pipelines_use_least_privilege._CHECK_ID = CHECK_ID
check_pipelines_use_least_privilege._CHECK_NAME = CHECK_NAME
