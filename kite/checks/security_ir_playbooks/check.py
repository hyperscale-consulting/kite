"""Check for security incident response playbooks."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "security-ir-playbooks"
CHECK_NAME = "Security Incident Response Playbooks"


def check_security_ir_playbooks() -> Dict[str, Any]:
    """
    Check if security incident response playbooks are in place for anticipated
    incidents such as DoS, ransomware, or credential compromise.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that security incident response playbooks are in "
        "place for anticipated incidents such as DoS, ransomware, or credential "
        "compromise.\n\n"
        "Consider the following factors:\n"
        "- Are playbooks available for common incident types (DoS, ransomware, "
        "credential compromise, data breach, malware)?\n"
        "- Do playbooks include prerequisites and dependencies?\n"
        "- Do playbooks clearly define who needs to be involved and their roles?\n"
        "- Do playbooks include step-by-step response procedures?\n"
        "- Do playbooks define expected outcomes and success criteria?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are security incident response playbooks in place for anticipated "
            "incidents such as DoS, ransomware, or credential compromise, "
            "including prerequisites, roles, response steps, and expected outcomes?"
        ),
        pass_message=(
            "Security incident response playbooks are in place for anticipated "
            "incidents with comprehensive details."
        ),
        fail_message=(
            "Security incident response playbooks should be in place for "
            "anticipated incidents with comprehensive details."
        ),
        default=True,
    )


check_security_ir_playbooks._CHECK_ID = CHECK_ID
check_security_ir_playbooks._CHECK_NAME = CHECK_NAME
