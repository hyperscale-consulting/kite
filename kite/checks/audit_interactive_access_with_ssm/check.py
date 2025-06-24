"""Check for auditing interactive access with SSM Session Manager."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "audit-interactive-access-with-ssm"
CHECK_NAME = "Audit Interactive Access with SSM"


def check_audit_interactive_access_with_ssm() -> Dict[str, Any]:
    """
    Check if interactive access, where required, is provided via SSM Session Manager
    and that session activity is logged in CloudWatch or S3 to provide an audit trail.

    This check asks the user to confirm that:
    1. Interactive access is provided via SSM Session Manager when needed
    2. Session activity is logged in CloudWatch or S3
    3. An audit trail is maintained for all interactive sessions

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that interactive access, where required, is provided "
        "via SSM Session Manager and that session activity is logged to provide "
        "an audit trail.\n\n"
        "Consider the following factors:\n"
        "- Is SSM Session Manager used for interactive access instead of "
        "direct SSH/RDP connections?\n"
        "- Is session activity logged to CloudWatch Logs or S3?\n"
        "- Are session logs retained for an appropriate period?\n"
        "- Is there monitoring and alerting for unusual session activity?\n"
        "- Are session logs reviewed regularly for security incidents?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is interactive access, where required, provided via SSM Session "
            "Manager with session activity logged in CloudWatch or S3 to "
            "provide an audit trail?"
        ),
        pass_message=(
            "Interactive access is provided via SSM Session Manager with "
            "proper audit logging in place."
        ),
        fail_message=(
            "Interactive access should be provided via SSM Session Manager "
            "with proper audit logging in place."
        ),
        default=True,
    )


check_audit_interactive_access_with_ssm._CHECK_ID = CHECK_ID
check_audit_interactive_access_with_ssm._CHECK_NAME = CHECK_NAME
