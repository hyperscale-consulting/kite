"""Check for regular review of CI/CD pipeline permissions."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "review-pipeline-permissions-regularly"
CHECK_NAME = "Regular Pipeline Permissions Review"


def check_review_pipeline_permissions_regularly() -> dict[str, Any]:
    """
    Check if permissions granted to CI/CD pipeline roles are reviewed regularly.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that permissions granted to CI/CD pipeline roles are "
        "reviewed regularly.\n\n"
        "Consider the following factors:\n"
        "- Are pipeline role permissions reviewed on a regular schedule?\n"
        "- Are unused permissions identified and removed?"
    )
    prompt = "Are permissions granted to CI/CD pipeline roles reviewed regularly?"

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Permissions granted to CI/CD pipeline roles are reviewed regularly."
        ),
        fail_message=(
            "Permissions granted to CI/CD pipeline roles should be reviewed regularly."
        ),
        default=True,
    )


check_review_pipeline_permissions_regularly._CHECK_ID = CHECK_ID
check_review_pipeline_permissions_regularly._CHECK_NAME = CHECK_NAME
