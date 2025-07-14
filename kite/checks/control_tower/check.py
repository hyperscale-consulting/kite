"""Check for use of Control Tower to enable suitable standard controls."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "control-tower"
CHECK_NAME = "Control Tower"


def check_control_tower() -> dict[str, Any]:
    """
    Check if Control Tower is used to enable suitable standard controls.


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
        "This check verifies that Control Tower is used to enable suitable standard "
        "controls.\n\n"
        "Consider the following factors:\n"
        "- Is Control Tower used to enable standard controls?\n"
        "- Are the standard controls suitable for the organization?\n"
        "- Are the standard controls consistently applied across all accounts?"
    )
    prompt = "Is Control Tower used to enable suitable standard controls?"

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=("Control Tower is used to enable suitable standard controls."),
        fail_message=(
            "Control Tower should be used to enable suitable standard controls."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_control_tower._CHECK_ID = CHECK_ID
check_control_tower._CHECK_NAME = CHECK_NAME
