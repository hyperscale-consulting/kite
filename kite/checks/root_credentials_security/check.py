"""Check for secure root credentials storage and access procedures."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "root-credentials-security"
CHECK_NAME = "Root Credentials Security"


def check_root_credentials_security() -> dict[str, Any]:
    """
    Check if root credentials are stored securely and accessed according to proper
    procedures.

    This is a manual check that prompts the user to verify:
    1. Root credentials are stored securely (e.g., password manager for passwords,
       safe for MFA devices)
    2. A two-person rule is in place so that no single person has access to all
       necessary credentials

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
        "This check verifies that root credentials are stored securely and accessed "
        "according to proper procedures.\n\n"
        "Consider the following factors:\n"
        "- Are root credentials stored securely? (e.g., password manager for "
        "passwords, safe for MFA devices)\n"
        "- Is a two-person rule in place so that no single person has access to all "
        "necessary credentials for the root account?"
    )
    prompt = (
        "Are root credentials stored securely and accessed according to proper "
        "procedures?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Root credentials are stored securely and accessed according to proper "
            "procedures."
        ),
        fail_message=(
            "Root credentials storage or access procedures need improvement."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_root_credentials_security._CHECK_ID = CHECK_ID
check_root_credentials_security._CHECK_NAME = CHECK_NAME
