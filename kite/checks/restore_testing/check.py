"""Check for restore testing of backups."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "restore-testing"
CHECK_NAME = "Restore Testing"


# TODO: add permissions to fetch restore testing plans and automate this check
def check_restore_testing() -> Dict[str, Any]:
    """
    Check if backups are regularly tested for restore viability and duration.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "Please review your backup restore testing procedures and confirm:\n\n"
        "1. Backups are regularly tested for restore viability\n"
        "2. Restore job duration is monitored and documented\n"
        "3. Restore testing results are reviewed and any issues are addressed\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are backups regularly tested for restore viability and restore job "
            "duration?"
        ),
        pass_message=(
            "Backups are regularly tested for restore viability and restore job "
            "duration."
        ),
        fail_message=(
            "Backups should be regularly tested for restore viability and restore "
            "job duration."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_restore_testing._CHECK_ID = CHECK_ID
check_restore_testing._CHECK_NAME = CHECK_NAME
