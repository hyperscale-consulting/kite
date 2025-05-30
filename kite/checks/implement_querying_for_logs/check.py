"""Check for log querying mechanisms."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "implement-querying-for-logs"
CHECK_NAME = "Log Querying Mechanisms"


def check_log_querying() -> Dict[str, Any]:
    """
    Check if there are mechanisms in place for querying and analyzing logs.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that appropriate mechanisms are in place for "
        "querying and analyzing logs.\n\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt="Do you have appropriate mechanisms for querying and analyzing logs?",
        pass_message="Appropriate log querying mechanisms are in place",
        fail_message="Log querying mechanisms need to be implemented or reviewed",
        default=True,
    )


# Attach the check ID and name to the function
check_log_querying._CHECK_ID = CHECK_ID
check_log_querying._CHECK_NAME = CHECK_NAME
