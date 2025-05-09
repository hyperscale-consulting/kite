"""Check for threat intelligence monitoring."""

from kite.helpers import manual_check


CHECK_ID = "threat-intelligence-monitoring"
CHECK_NAME = "Threat Intelligence Monitoring"


def check_threat_intelligence_monitoring():
    """Check if teams have a reliable and repeatable mechanism to stay informed of the
    latest threat intelligence.

    Returns:
        dict: A dictionary containing the check results.
    """
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=(
            "Do teams have a reliable and repeatable mechanism "
            "to stay informed of the latest threat intelligence.\n\n"
            "Consider the following factors:\n"
            "- Do teams regularly review the MITRE ATTACK knowledge base?\n"
            "- Are teams monitoring MITRE's CVE list for relevant vulnerabilities?\n"
            "- Do teams stay updated with the OWASP top 10 lists?\n"
            "- Do teams subscribe to and review security blogs and bulletins "
            "(e.g., AWS Security Bulletins)?\n"
        ),
        prompt=(
            "Do teams have a reliable and repeatable mechanism to stay informed of "
            "the latest threat intelligence?"
        ),
        pass_message=(
            "Teams have established reliable and repeatable mechanisms to stay "
            "informed of the latest threat intelligence."
        ),
        fail_message=(
            "Teams lack reliable and repeatable mechanisms to stay informed of the "
            "latest threat intelligence."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_threat_intelligence_monitoring._CHECK_ID = CHECK_ID
check_threat_intelligence_monitoring._CHECK_NAME = CHECK_NAME
