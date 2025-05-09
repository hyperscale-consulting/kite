"""Check for effective use of AWS managed services with automatic threat intelligence
updates."""

# TODO: automated support for this check - required addition permissions

from kite.helpers import manual_check


CHECK_ID = "aws-managed-services-threat-intel"
CHECK_NAME = "AWS Managed Services Threat Intelligence"


def check_aws_managed_services_threat_intel():
    """Check if AWS managed services that automatically update with the latest threat
    intelligence are used effectively.

    Returns:
        dict: A dictionary containing the check results.
    """
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=(
            "Are AWS managed services that automatically update "
            "with the latest threat intelligence are used effectively.\n\n"
            "Consider the following factors:\n"
            "- Are AWS managed services with built-in threat intelligence being used "
            "where appropriate? (e.g GuardDuty, WAF, Inspector, Shield Advanced)"
        ),
        prompt=(
            "Are AWS managed services that automatically update with the latest threat "
            "intelligence used effectively?"
        ),
        pass_message=(
            "Teams effectively use AWS managed services with automatic threat "
            "intelligence updates."
        ),
        fail_message=(
            "Teams do not effectively use AWS managed services with automatic threat "
            "intelligence updates."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_aws_managed_services_threat_intel._CHECK_ID = CHECK_ID
check_aws_managed_services_threat_intel._CHECK_NAME = CHECK_NAME
