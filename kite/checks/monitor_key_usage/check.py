"""Check if key usage is audited and monitored for unusual patterns."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "monitor-key-usage"
CHECK_NAME = "Monitor Key Usage"


def check_monitor_key_usage() -> Dict[str, Any]:
    """
    Check if key usage is audited and monitored for unusual patterns.

    This check asks the user to confirm that key usage is being monitored for:
    - Unusual access patterns
    - Important cryptographic events such as key deletion
    - Rotation of key material
    - Imported key material nearing its expiry date
    - High rates of decryption failures

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that key usage is audited and monitored for "
        "unusual patterns and important cryptographic events."
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is key usage audited, with monitoring set up to detect and alert on "
            "unusual access patterns, important cryptographic events such as key "
            "deletion, rotation of key material, imported key material nearing "
            "its expiry date, or high rates of decryption failures?"
        ),
        pass_message=(
            "Key usage is being audited and monitored for unusual patterns and "
            "important cryptographic events."
        ),
        fail_message=(
            "Key usage should be audited and monitored for unusual patterns and "
            "important cryptographic events."
        ),
        default=True,
    )


check_monitor_key_usage._CHECK_ID = CHECK_ID
check_monitor_key_usage._CHECK_NAME = CHECK_NAME
