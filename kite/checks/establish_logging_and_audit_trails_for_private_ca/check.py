"""Check for logging and audit trails for private CAs."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "establish-logging-and-audit-trails-for-private-ca"
CHECK_NAME = "Establish Logging and Audit Trails for Private CA"


def check_establish_logging_and_audit_trails_for_private_ca() -> dict[str, Any]:
    """
    Check if logging and audit trails are established for private CAs.

    This check verifies that:
    1. CloudTrail logs are monitored for and alert on unauthorized activity
    2. Audit reports listing certificates issued and revoked are periodically reviewed

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that logging and audit trails are established for "
        "private CAs.\n\n"
        "Consider the following factors:\n"
        "- Are CloudTrail logs monitored for unauthorized activity related to "
        "private CAs?\n"
        "- Are alerts configured for suspicious or unauthorized CA operations?\n"
        "- Are audit reports listing certificates issued and revoked "
        "periodically reviewed?\n"
        "- Is there a process to investigate and respond to unauthorized "
        "certificate operations?\n"
        "- Are audit logs retained for a sufficient period to support "
        "investigations?\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are CloudTrail logs monitored for unauthorized activity and are audit "
            "reports listing certificates issued and revoked periodically reviewed?"
        ),
        pass_message=(
            "Logging and audit trails are established for private CAs, with "
            "monitoring of unauthorized activity and periodic review of audit reports."
        ),
        fail_message=(
            "Logging and audit trails should be established for private CAs, with "
            "monitoring of unauthorized activity and periodic review of audit reports."
        ),
        default=False,
    )


check_establish_logging_and_audit_trails_for_private_ca._CHECK_ID = CHECK_ID
check_establish_logging_and_audit_trails_for_private_ca._CHECK_NAME = CHECK_NAME
