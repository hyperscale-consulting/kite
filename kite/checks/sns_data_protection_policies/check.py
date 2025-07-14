"""Check for SNS data protection policies."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "sns-data-protection-policies"
CHECK_NAME = "SNS Data Protection Policies"


def check_sns_data_protection_policies() -> dict[str, Any]:
    """
    Check if SNS data protection policies are used to automatically identify
    and mask unexpected sensitive data in SNS messages.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    # TODO: Add permissions so we can do some automated support with this check.
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=(
            "This check verifies that SNS data protection policies are used "
            "to automatically identify and mask unexpected sensitive data in "
            "SNS messages.\n\n"
            "Consider the following factors:\n"
            "- Are data protection policies configured for SNS topics?\n"
            "- Are alarms in place to alert on unexpected sensitive data?\n"
            "- Is sensitive data denied, masked or redacted as appropriate?\n"
            "- Do the policies align with your data classification scheme and inventory?"
        ),
        prompt=(
            "Are SNS data protection policies used to automatically identify, "
            "mask and alert on unexpected sensitive data in SNS messages?"
        ),
        pass_message=(
            "SNS data protection policies are used to automatically identify, "
            "mask and alert on unexpected sensitive data in SNS messages."
        ),
        fail_message=(
            "SNS data protection policies should be used to automatically "
            "identify, mask and alert on unexpected sensitive data in SNS "
            "messages."
        ),
        default=True,
    )


check_sns_data_protection_policies._CHECK_ID = CHECK_ID
check_sns_data_protection_policies._CHECK_NAME = CHECK_NAME
