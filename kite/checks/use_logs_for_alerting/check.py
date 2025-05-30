"""Check for log-based alerting mechanisms."""

from typing import Dict, Any, List

from kite.config import Config
from kite.helpers import (
    manual_check,
    ProwlerResult,
    get_prowler_output,
)


CHECK_ID = "use-logs-for-alerting"
CHECK_NAME = "Log-Based Alerting"


def _check_passed(checks: Dict[str, List[ProwlerResult]], check_id: str) -> bool:
    """
    Get the status of a specific Prowler check.

    Args:
        checks: List of Prowler check results
        check_id: ID of the check to find

    Returns:
        Status of the check or "Not Found" if check doesn't exist
    """
    config = Config.get()
    if check_id in checks:
        results = checks[check_id]
        for result in results:
            if result.status != "PASS" and result.region in config.active_regions:
                return False
        return True
    raise ValueError(f"Check {check_id} not found")


def check_log_alerting() -> Dict[str, Any]:
    """
    Check if logs are being used for alerting on potentially malicious or
    unauthorized behavior.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    # Get Prowler check results
    prowler_results = get_prowler_output()
    guardduty_passed = _check_passed(prowler_results, "guardduty_is_enabled")
    securityhub_passed = _check_passed(prowler_results, "securityhub_enabled")

    message = (
        "This check verifies that logs are being used for alerting on "
        "potentially malicious or unauthorized behavior.\n\n"
        "Please confirm if you have implemented alerting for:\n"
        "1. CloudTrail logs (e.g., unauthorized API calls, console logins, "
        "IAM changes)\n"
        "2. VPC Flow Logs (e.g., unusual traffic patterns, connections to "
        "known malicious IPs)\n"
        "3. CloudWatch Logs (e.g., application errors, security events)\n"
        "4. AWS Config (e.g., configuration changes, compliance violations)\n"
        "5. Route53 Resolver Query Logs (e.g., DNS exfiltration attempts)\n"
        "6. Application specific logs\n\n"
        "Additional Context:\n"
        f"- GuardDuty Status: {'Enabled' if guardduty_passed else 'Disabled'}\n"
        f"- SecurityHub Status: {'Enabled' if securityhub_passed else 'Disabled'}\n\n"
        "Note: GuardDuty and SecurityHub can provide additional alerting "
        "capabilities for security events."
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Do you use logs for alerting on potentially malicious or "
            "unauthorized behavior?"
        ),
        pass_message="Log-based alerting mechanisms are in place",
        fail_message="Log-based alerting mechanisms need to be implemented or reviewed",
        default=True,
    )


# Attach the check ID and name to the function
check_log_alerting._CHECK_ID = CHECK_ID
check_log_alerting._CHECK_NAME = CHECK_NAME
