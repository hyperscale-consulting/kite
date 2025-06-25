"""Check for capturing key contacts for security incident response."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "capture-key-contacts"
CHECK_NAME = "Capture Key Contacts"


def check_capture_key_contacts() -> Dict[str, Any]:
    """
    Check if the contact details of key personnel and external resources are
    captured and documented so that the right people can be involved in
    responding to a security event.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that the contact details of key personnel and "
        "external resources are captured and documented so that the right "
        "people can be involved in responding to a security event.\n\n"
        "Consider the following factors:\n"
        "- Are contact details for key personnel documented?\n"
        "- Are contact details for external partners documented?\n"
        "- Is there a process for keeping contact information up to date?\n"
        "- Are contact details accessible during a security incident?\n"
        "- Are roles and responsibilities for contacts defined?\n"
        "- Are there a clear escalation paths?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are the contact details of key personnel and external resources "
            "captured and documented so that the right people can be involved "
            "in responding to a security event?"
        ),
        pass_message=(
            "Contact details of key personnel and external resources are "
            "captured and documented for security incident response."
        ),
        fail_message=(
            "Contact details of key personnel and external resources should be "
            "captured and documented for security incident response."
        ),
        default=True,
    )


check_capture_key_contacts._CHECK_ID = CHECK_ID
check_capture_key_contacts._CHECK_NAME = CHECK_NAME
