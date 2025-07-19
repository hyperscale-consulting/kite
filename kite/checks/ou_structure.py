"""OU structure check module."""

from kite.data import get_organization
from kite.helpers import get_organization_structure_str
from kite.helpers import manual_check

CHECK_ID = "ou-structure"
CHECK_NAME = "OU Structure"


def check_ou_structure() -> dict:
    """
    Check if there is an effective OU structure in the organization.

    Returns:
        A dictionary containing the finding for the OU Structure check.
    """
    org = get_organization()
    if org is None:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "AWS Organizations is not being used, so OU structure "
                    "cannot be assessed."
                ),
            },
        }

    # Get the organization structure
    org_structure = get_organization_structure_str(org)

    # Create the message for the panel
    message = (
        "Consider the following factors for OU structure:\n"
        "- Are OUs used to group accounts based on function, compliance "
        "requirements, or a common set of controls?\n\n"
        "Organization Structure:\n"
        f"{org_structure}"
    )

    # Use manual_check to get the user's response
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt="Is there an effective OU structure?",
        pass_message="Effective OU structure is in place.",
        fail_message="OU structure could be improved.",
        default=True,
    )


# Attach the check ID and name to the function
check_ou_structure._CHECK_ID = CHECK_ID
check_ou_structure._CHECK_NAME = CHECK_NAME
