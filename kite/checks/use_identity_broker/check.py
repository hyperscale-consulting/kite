"""Check for use of identity broker for temporary privilege escalation."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "use-identity-broker"
CHECK_NAME = "Use Identity Broker for Temporary Privilege Escalation"


def check_use_identity_broker() -> dict[str, Any]:
    """
    Check if an identity broker is used for temporary privilege escalation.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that an identity broker is used to request and "
        "approve temporary elevated privileges to responders in the event of "
        "an incident, as opposed to JIT provisioning or credential vaulting.\n\n"
        "Consider the following factors:\n"
        "- Is an identity broker used for temporary privilege escalation?\n"
        "- Is there a request and approval workflow for elevated privileges?\n"
        "- Are elevated privileges time-limited and automatically revoked?\n"
        "- Is there a clear process for requesting elevated access during incidents?\n"
        "- Are approvals documented and auditable?\n"
        "- Are elevated privileges limited to what is necessary for incident response?\n"
        "- Is there monitoring and alerting for elevated privilege usage?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is an identity broker used to request and approve temporary "
            "elevated privileges for incident responders?"
        ),
        pass_message=(
            "Identity broker is used for temporary privilege escalation "
            "with proper approval workflows."
        ),
        fail_message=(
            "An identity broker should be used for temporary privilege "
            "escalation during incidents."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_use_identity_broker._CHECK_ID = CHECK_ID
check_use_identity_broker._CHECK_NAME = CHECK_NAME
