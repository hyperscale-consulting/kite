"""Check for identity auditing."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "identity-audit"
CHECK_NAME = "Identity Audit"


def check_identity_audit() -> dict[str, Any]:
    """
    Check if credentials and identities are regularly audited.

    Returns:
        Dict containing the check results.
    """
    context_message = (
        "This check verifies that credentials and identities are regularly audited.\n\n"
        "Consider the following factors:\n"
        "- Are IAM users / Identity Center users / IdP users regularly reviewed to "
        "ensure that only authorized users have access?\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=context_message,
        prompt="Are credentials and identities regularly audited?",
        pass_message="Credentials and identities are regularly audited",
        fail_message="Credentials and identities should be regularly audited",
        default=True,
    )


# Attach the check ID and name to the function
check_identity_audit._CHECK_ID = CHECK_ID
check_identity_audit._CHECK_NAME = CHECK_NAME
