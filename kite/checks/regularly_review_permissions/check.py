"""Check for regular review and removal of unused permissions."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "regularly-review-permissions"
CHECK_NAME = "Regularly Review Permissions"


def check_regularly_review_permissions() -> dict[str, Any]:
    """
    Check if permissions are reviewed regularly and unused permissions,
    identities, and policies are removed.

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
        "This check verifies that permissions are reviewed regularly and unused "
        "permissions, identities, and policies are removed.\n\n"
        "Consider the following factors:\n"
        "- Are permissions reviewed on a regular schedule (e.g., quarterly)?\n"
        "- Are unused users, roles, and groups removed?\n"
        "- Are unused policies (both inline and managed) removed?\n"
        "- Are unused permissions removed from policies?\n"
        "- Is there a documented process for permission reviews?\n"
        "- Are permission reviews tracked and documented?\n"
        "- Are findings from permission reviews acted upon?"
    )
    prompt = (
        "Are permissions reviewed regularly and unused permissions, identities, "
        "and policies removed?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Permissions are reviewed regularly and unused permissions, identities, "
            "and policies are removed."
        ),
        fail_message=(
            "Permissions should be reviewed regularly and unused permissions, "
            "identities, and policies should be removed."
        ),
        default=False,
    )

    return result


# Attach the check ID and name to the function
check_regularly_review_permissions._CHECK_ID = CHECK_ID
check_regularly_review_permissions._CHECK_NAME = CHECK_NAME
