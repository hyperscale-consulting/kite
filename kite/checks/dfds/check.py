"""Check for up-to-date DFDs capturing trust boundaries and data flows."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "dfds"
CHECK_NAME = "Data Flow Diagrams"


def check_dfds() -> Dict[str, Any]:
    """
    Check if there are up-to-date DFDs capturing all major trust boundaries,
    data flows and components.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    # Define the message and prompts
    message = (
        "This check verifies that there are up-to-date DFDs capturing all major "
        "trust boundaries, data flows and components.\n\n"
        "Consider the following factors:\n"
        "- Are DFDs up-to-date?\n"
        "- Do DFDs capture all major trust boundaries?\n"
        "- Do DFDs capture all data flows and components?"
    )
    prompt = (
        "Are there up-to-date DFDs capturing all major trust boundaries, data "
        "flows and components?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "There are up-to-date DFDs capturing all major trust boundaries, data "
            "flows and components."
        ),
        fail_message=(
            "There should be up-to-date DFDs capturing all major trust boundaries, "
            "data flows and components."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_dfds._CHECK_ID = CHECK_ID
check_dfds._CHECK_NAME = CHECK_NAME
