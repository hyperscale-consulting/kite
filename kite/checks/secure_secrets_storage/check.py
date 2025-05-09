"""Check for secure storage of secrets in a secure platform."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "secure-secrets-storage"
CHECK_NAME = "Secure Secrets Storage"


def check_secure_secrets_storage() -> Dict[str, Any]:
    """
    Check if all secrets are stored in a secure platform (i.e. encrypted, auditable, etc).

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
        "This check verifies that all secrets are stored in a secure platform "
        "(e.g. AWS Secrets Manager, HashiCorp Vault, etc)."
    )
    prompt = (
        "Are all secrets stored in a secure platform (i.e. encrypted, auditable, etc)?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "All secrets are stored in a secure platform with proper encryption "
            "and audit capabilities."
        ),
        fail_message=(
            "Secrets should be stored in a secure platform with proper encryption "
            "and audit capabilities."
        ),
        default=True,
    )

    return result


check_secure_secrets_storage._CHECK_ID = CHECK_ID
check_secure_secrets_storage._CHECK_NAME = CHECK_NAME
