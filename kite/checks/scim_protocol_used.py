"""Check if SCIM protocol is used for IAM Identity Center synchronization."""

from typing import Any

from kite.helpers import is_identity_center_enabled
from kite.helpers import manual_check

CHECK_ID = "scim-protocol-used"
CHECK_NAME = "SCIM Protocol Used for IAM Identity Center"


def check_scim_protocol_used() -> dict[str, Any]:
    """
    Check if SCIM protocol is used to synchronize user and group information from
    the external identity provider into IAM Identity Center's data store.

    This check:
    1. Verifies if Identity Center is enabled
    2. Asks the user if SCIM protocol is used for synchronization

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """

    identity_center_enabled = is_identity_center_enabled()

    if not identity_center_enabled:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {"message": "Identity Center is not enabled."},
        }

    # Build the context message
    context_message = (
        "This check verifies that SCIM protocol is used to synchronize user and "
        "group information from the external identity provider into IAM Identity "
        "Center's data store.\n\n"
        "Consider the following factors:\n"
        "- Is SCIM protocol configured for user synchronization?\n"
        "- Is SCIM protocol configured for group synchronization?\n"
        "- Are changes in the external identity provider automatically reflected "
        "in IAM Identity Center?\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=context_message,
        prompt=(
            "Is SCIM protocol used to synchronize user and group information "
            "from the external identity provider into IAM Identity Center's data store?"
        ),
        pass_message=("SCIM protocol is used for IAM Identity Center synchronization."),
        fail_message=(
            "SCIM protocol should be used for IAM Identity Center synchronization."
        ),
        default=False,
    )


check_scim_protocol_used._CHECK_ID = CHECK_ID
check_scim_protocol_used._CHECK_NAME = CHECK_NAME
