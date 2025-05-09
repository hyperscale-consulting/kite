"""Check for regular threat modeling by teams."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "threat-modeling"
CHECK_NAME = "Threat Modeling"


def check_threat_modeling() -> Dict[str, Any]:
    """
    Check if teams perform threat modeling regularly.

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
        "This check verifies that teams perform threat modeling regularly.\n\n"
        "Consider the following factors:\n"
        "- Do teams perform threat modeling regularly?\n"
        "- Is threat modeling part of the development process?\n"
        "- Are threat modeling results documented and reviewed?"
    )
    prompt = "Do teams threat model regularly?"

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message="Teams perform threat modeling regularly.",
        fail_message="Teams should perform threat modeling regularly.",
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_threat_modeling._CHECK_ID = CHECK_ID
check_threat_modeling._CHECK_NAME = CHECK_NAME
