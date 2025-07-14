"""Check for automated forensics collection."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "automate-forensics"
CHECK_NAME = "Automate Forensics"


def check_automate_forensics() -> dict[str, Any]:
    """
    Check if the collection of forensics, such as snapshots of EBS volumes,
    memory dumps, process lists etc is automated.

    This check asks the user to confirm that:
    1. Forensic collection is automated where possible
    2. Various types of forensics are collected automatically
    3. The automation is reliable and comprehensive

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that the collection of forensics, such as snapshots "
        "of EBS volumes, memory dumps, process lists and logs is automated as far as "
        "possible.\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is the collection of forensics, such as snapshots of EBS volumes, "
            "memory dumps, process lists and logs automated?"
        ),
        pass_message=(
            "Forensic collection is automated for various types of evidence."
        ),
        fail_message=(
            "Forensic collection should be automated for various types of evidence."
        ),
        default=True,
    )


check_automate_forensics._CHECK_ID = CHECK_ID
check_automate_forensics._CHECK_NAME = CHECK_NAME
