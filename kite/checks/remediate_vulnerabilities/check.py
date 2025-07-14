"""Check for vulnerability remediation processes."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "remediate-vulnerabilities"
CHECK_NAME = "Remediate Vulnerabilities"


def check_remediate_vulnerabilities() -> dict[str, Any]:
    """
    Check if there are processes and procedures in place to prioritize and remediate
    identified vulnerabilities based on risk assessment criteria.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that there are processes and procedures in place to "
        "prioritize and remediate identified vulnerabilities based on risk "
        "assessment criteria.\n\n"
        "Consider the following factors:\n"
        "- Are vulnerabilities triaged and prioritized based on risk?\n"
        "- Are there defined SLAs for remediation based on severity?\n"
        "- Are remediation actions tracked and reviewed?"
    )
    prompt = (
        "Are there processes and procedures in place to prioritize and remediate "
        "identified vulnerabilities based on risk assessment criteria?"
    )
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "There are processes and procedures in place to prioritize and remediate "
            "identified vulnerabilities based on risk assessment criteria."
        ),
        fail_message=(
            "Processes and procedures should be established to prioritize and "
            "remediate identified vulnerabilities based on risk assessment criteria."
        ),
        default=True,
    )


check_remediate_vulnerabilities._CHECK_ID = CHECK_ID
check_remediate_vulnerabilities._CHECK_NAME = CHECK_NAME
