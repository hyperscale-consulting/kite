"""Isolation boundaries check module."""

from kite.data import get_organization

from kite.helpers import (
    get_organization_structure_str,
    manual_check,
)

CHECK_ID = "define-and-enforce-isolation-boundaries"
CHECK_NAME = "Define and Enforce Isolation Boundaries"


def check_isolation_boundaries() -> dict:
    """
    Check if data of different sensitivity levels are properly isolated using accounts
    and SCPs.

    Returns:
        A dictionary containing the finding for the Isolation Boundaries check.
    """
    org = get_organization()
    if org is None:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "AWS Organizations is not being used, so isolation boundaries "
                    "cannot be assessed."
                ),
            },
        }

    # Get the organization structure
    org_structure = get_organization_structure_str(org)

    # Create the message for the panel
    message = (
        "Consider the following factors for isolation boundaries:\n"
        "- Are data of different sensitivity levels (e.g., public, internal, "
        "confidential, restricted) stored in separate accounts?\n"
        "- Are Service Control Policies (SCPs) used to control which services and "
        "actions are allowed for each data sensitivity level?\n\n"
        "Organization Structure:\n"
        f"{org_structure}"
    )

    # Use manual_check to get the user's response
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are data of different sensitivity levels properly isolated using "
            "accounts and SCPs?"
        ),
        pass_message="Effective isolation boundaries are in place.",
        fail_message="Isolation boundaries could be improved.",
        default=True,
    )
