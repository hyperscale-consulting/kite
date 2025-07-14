"""Check for forensic OU with dedicated accounts."""

from typing import Any

from kite.data import get_organization
from kite.helpers import get_organization_structure_str
from kite.helpers import manual_check

CHECK_ID = "forensics-ou"
CHECK_NAME = "Forensics OU"


def check_forensics_ou() -> dict[str, Any]:
    """
    Check if there is a forensic OU with one or more accounts dedicated to
    capturing forensics for analysis in the event of a security incident.

    This check asks the user to confirm that:
    1. There is a forensic OU in the organization
    2. The forensic OU contains one or more dedicated accounts
    3. These accounts are used for capturing forensics for analysis

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    org = get_organization()
    if org is None:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "AWS Organizations is not being used, so forensic OU "
                    "structure cannot be assessed."
                ),
            },
        }

    # Get the organization structure
    org_structure = get_organization_structure_str(org)

    # Create the message for the panel
    message = (
        "This check verifies that there is a forensic OU with one or more "
        "accounts dedicated to capturing forensics for analysis in the event "
        "of a security incident.\n\n"
        "Consider the following factors:\n"
        "- Is there a dedicated OU for forensic activities?\n"
        "- Does the forensic OU contain one or more dedicated accounts?\n"
        "- Are these accounts used specifically for capturing forensics?\n"
        "Organization Structure:\n"
        f"{org_structure}"
    )

    # Use manual_check to get the user's response
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is there a forensic OU with one or more accounts dedicated to "
            "capturing forensics for analysis in the event of a security incident?"
        ),
        pass_message=(
            "A forensic OU with dedicated accounts for capturing forensics is in place."
        ),
        fail_message=(
            "A forensic OU with dedicated accounts for capturing forensics "
            "should be established."
        ),
        default=True,
    )


check_forensics_ou._CHECK_ID = CHECK_ID
check_forensics_ou._CHECK_NAME = CHECK_NAME
