"""Check for identification and addressing of security risks."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "security-risks"
CHECK_NAME = "Security Risks"


def check_security_risks() -> dict[str, Any]:
    """
    Check if teams have done a good job at identifying and addressing security risks.


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
        "This check verifies that teams have done a good job at identifying and "
        "addressing security risks.\n\n"
        "Consider the following factors:\n"
        "- Have teams identified security risks - are there any obvious STRIDE "
        "threats missing?\n"
        "- Have teams addressed identified security risks? For example, have they "
        "been tracked as bugs and fixed? Are those mitigations suitable?\n"
        "- Is the process for identifying and addressing risks effective?"
    )
    prompt = (
        "Have teams done a good job at identifying (and addressing) security risks?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Teams have done a good job at identifying and addressing security risks."
        ),
        fail_message=(
            "Teams should do a better job at identifying and addressing security risks."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_security_risks._CHECK_ID = CHECK_ID
check_security_risks._CHECK_NAME = CHECK_NAME
