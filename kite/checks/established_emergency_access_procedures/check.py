"""Check for established emergency access procedures."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "established-emergency-access-procedures"
CHECK_NAME = "Establish emergency access procedures"


def check_emergency_access_procedures() -> dict[str, Any]:
    """
    Check if emergency access procedures are properly established and documented.

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
        "This check verifies that emergency access procedures are properly established "
        "and documented.\n\n"
        "Consider the following factors:\n"
        "- Are there well documented emergency procedures covering - at a minimum - "
        "the 3 primary failure modes (IdP failure, IdP misconfiguration, Identity Center failure)?\n"
        "- Do processes have pre-conditions and assumptions documented explaining when "
        "the process should be used and when it should not be used, for each failure mode?\n"
        "- Is there a dedicated AWS account that is used for emergency access?\n"
        "- Are there dedicated IAM accounts, protected by strong passwords and MFA, \n"
        "for each emergency incident responder?\n"
        "- Are all resources required by the emergency access processes pre-created?\n"
        "- Are emergency access processes included in incident management plans?\n"
        "- Can the emergency access process only be initiated by authorized users?\n"
        "- Does the emergency access process require approval from peers / management\n"
        "- Is robust logging, monitoring and alerting in place for the emergency access "
        "process and mechanisms?\n"
        "- Are emergency access processes tested periodically?\n"
        "- Are emergency access mechanisms disabled during normal operation?"
    )
    prompt = "Are emergency access procedures properly established?"

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Emergency access procedures are properly established and documented, "
            "covering all required aspects."
        ),
        fail_message=(
            "Emergency access procedures should be properly established and documented, "
            "covering all required aspects."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_emergency_access_procedures._CHECK_ID = CHECK_ID
check_emergency_access_procedures._CHECK_NAME = CHECK_NAME
