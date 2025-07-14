"""Check for monitoring of secrets for unusual activity."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "monitor-secrets"
CHECK_NAME = "Monitor Secrets"


def check_monitor_secrets() -> dict[str, Any]:
    """
    Check if secrets are monitored for unusual activity and if automated
    remediation actions are triggered where appropriate.

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
        "This check verifies that secrets are monitored for unusual activity and "
        "that automated remediation actions are triggered where appropriate.\n\n"
        "Consider the following factors:\n"
        "- Are secrets monitored for unusual access patterns, such as attempts to "
        "delete secrets, or attempts to read secrets from unexpected princpals or "
        "networks?\n"
        "- Are automated remediation actions triggered for suspicious activity?\n"
        "- Are alerts sent to appropriate teams for investigation?"
    )
    prompt = (
        "Are secrets monitored for unusual activity and are automated remediation "
        "actions triggered where appropriate?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Secrets are monitored for unusual activity and automated remediation "
            "actions are triggered where appropriate."
        ),
        fail_message=(
            "Secrets should be monitored for unusual activity and automated "
            "remediation actions should be triggered where appropriate."
        ),
        default=True,
    )

    return result


check_monitor_secrets._CHECK_ID = CHECK_ID
check_monitor_secrets._CHECK_NAME = CHECK_NAME
