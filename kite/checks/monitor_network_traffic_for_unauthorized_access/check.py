"""Check for monitoring network traffic for unauthorized access."""

from typing import Dict, Any

from kite.helpers import manual_check

CHECK_ID = "monitor-network-traffic-for-unauthorized-access"
CHECK_NAME = "Monitor Network Traffic for Unauthorized Access"


def check_monitor_network_traffic_for_unauthorized_access() -> Dict[str, Any]:
    """
    Check if network traffic is continually monitored for unintended communication
    channels, unauthorized principals attempting to access protected resources, and
    other improper access patterns.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that network traffic is continually monitored for "
        "unintended communication channels, unauthorized principals attempting to "
        "access protected resources, and other improper access patterns.\n\n"
        "Consider the following factors:\n"
        "- Is network traffic monitored for unexpected or unauthorized communication "
        "  channels?\n"
        "- Are there controls in place to detect unauthorized principals attempting "
        "  to access protected resources?\n"
        "- Are improper or suspicious access patterns detected and investigated?\n"
        "- Are alerts generated and responded to in a timely manner?"
    )
    prompt = (
        "Is network traffic continually monitored for unintended communication "
        "channels, unauthorized principals attempting to access protected resources, "
        "and other improper access patterns?"
    )

    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Network traffic is continually monitored for unintended communication "
            "channels, unauthorized principals, and improper access patterns."
        ),
        fail_message=(
            "Network traffic should be continually monitored for unintended "
            "communication channels, unauthorized principals, and improper access "
            "patterns."
        ),
        default=True,
    )

    return result


check_monitor_network_traffic_for_unauthorized_access._CHECK_ID = CHECK_ID
check_monitor_network_traffic_for_unauthorized_access._CHECK_NAME = CHECK_NAME
