"""Account separation check module."""

from kite.data import get_organization
from kite.helpers import get_organization_structure_str
from kite.helpers import prompt_user_with_panel

CHECK_ID = "account-separation"
CHECK_NAME = "Account Separation"


def check_account_separation() -> dict:
    """
    Check if there is effective account separation in the organization.

    Returns:
        A dictionary containing the finding for the Account Separation check.
    """
    org = get_organization()
    if org is None:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "AWS Organizations is not being used, so account separation "
                    "cannot be assessed."
                ),
            },
        }

    # Get the organization structure
    org_structure = get_organization_structure_str(org)

    # Create the message for the panel
    message = (
        "Consider the following factors for account separation:\n"
        "- Are unrelated workloads, or workloads with different data "
        "sensitivity, separated into different accounts?\n"
        "- Are dev, test, dev tooling, deployment, etc accounts separated from "
        "workload accounts?\n"
        "- Are there separate log archive and audit (AKA security tooling) "
        "accounts?\n\n"
        "Organization Structure:\n"
        f"{org_structure}"
    )

    # Use prompt_user_with_panel to get the user's response
    effective_separation, _ = prompt_user_with_panel(
        check_name=CHECK_NAME,
        message=message,
        prompt="Is there effective account separation?",
        default=True,
    )

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS" if effective_separation else "FAIL",
        "details": {
            "message": (
                "Effective account separation is in place."
                if effective_separation
                else "Account separation could be improved."
            ),
        },
    }


# Attach the check ID and name to the function
check_account_separation._CHECK_ID = CHECK_ID
check_account_separation._CHECK_NAME = CHECK_NAME
