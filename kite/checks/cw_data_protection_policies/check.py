"""Check for CloudWatch data protection policies."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "cw-data-protection-policies"
CHECK_NAME = "CloudWatch Data Protection Policies"


def check_cw_data_protection_policies() -> Dict[str, Any]:
    # TODO: Add permissions so we can do some automated support with this check.
    """
    Check if CloudWatch data protection policies are used to automatically identify
    and mask unexpected sensitive data in CloudWatch log files.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=(
            "This check verifies that CloudWatch data protection policies are used "
            "to automatically identify and mask unexpected sensitive data in "
            "CloudWatch log files.\n\n"
            "Consider the following factors:\n"
            "- Are data protection policies configured for CloudWatch log groups?\n"
            "- Are alarms in place to alert on unexpected sensitive data?\n"
            "- Do the policies align with your data classification scheme and inventory?\n"
        ),
        prompt=(
            "Are CloudWatch data protection policies used to automatically identify, "
            "mask and alert on unexpected sensitive data in CloudWatch log files?"
        ),
        pass_message=(
            "CloudWatch data protection policies are used to automatically identify, "
            "mask and alert on unexpected sensitive data in CloudWatch log files."
        ),
        fail_message=(
            "CloudWatch data protection policies should be used to automatically "
            "identify, mask and alert on unexpected sensitive data in CloudWatch log "
            "files."
        ),
        default=True,
    )


check_cw_data_protection_policies._CHECK_ID = CHECK_ID
check_cw_data_protection_policies._CHECK_NAME = CHECK_NAME
