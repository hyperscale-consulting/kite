"""Check for automated security event correlation and enrichment."""

from typing import Any

from kite.helpers import prompt_user_with_panel

CHECK_ID = "security-event-correlation"
CHECK_NAME = "Security Event Correlation and Enrichment"


def check_security_event_correlation() -> dict[str, Any]:
    """
    Check if there are automated mechanisms for security event correlation and enrichment.

    This check asks the user to confirm whether there are automated mechanisms for:
    1. Correlation of security events across different data sources
    2. Enrichment of security events with additional context
    3. Examples of data sources that should be correlated and enriched:
       - CloudTrail logs
       - VPC flow logs
       - Route 53 resolver logs
       - Infrastructure logs
       - Application logs

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "Security Event Correlation and Enrichment\n\n"
        "This check verifies that there are automated mechanisms for correlating and "
        "enriching security events across different data sources.\n\n"
        "Examples of data sources that can be used for correlation and enrichment:\n"
        "- CloudTrail logs\n"
        "- VPC flow logs\n"
        "- Route 53 resolver logs\n"
        "- Infrastructure logs\n"
        "- Application logs\n\n"
        "The correlation and enrichment process should:\n"
        "- Combine related events across different sources\n"
        "- Add context to security events - for example via notes and user defined "
        "fields in AWS Security Hub\n"
        "- Help identify patterns and anomalies\n"
        "- Support incident investigation and response"
    )

    # Ask the user to confirm if automated mechanisms exist
    has_mechanisms, _ = prompt_user_with_panel(
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are there automated mechanisms for correlating and enriching security "
            "events across these data sources?"
        ),
        default=True,
    )

    if has_mechanisms:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "Automated mechanisms exist for correlating and enriching security "
                    "events across different data sources."
                ),
            },
        }
    else:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "No automated mechanisms found for correlating and enriching "
                    "security events across different data sources."
                ),
            },
        }


check_security_event_correlation._CHECK_ID = CHECK_ID
check_security_event_correlation._CHECK_NAME = CHECK_NAME
