"""Check for security guardians program."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "security-guardians-program"
CHECK_NAME = "Security Guardians Program"


def check_security_guardians_program() -> dict[str, Any]:
    """
    Check if there is a program to embed security ownership and decision making in
    workload teams.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that there is a program to embed security ownership "
        "and decision making in workload teams.\n\n"
        "Consider the following factors:\n"
        "- Is there a formal program to embed security expertise in teams?\n"
        "- Do teams have clear ownership of security decisions?"
    )
    prompt = (
        "Is there a program to embed security ownership and decision making in "
        "workload teams?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "There is a program to embed security ownership and decision making in "
            "workload teams."
        ),
        fail_message=(
            "A program should be established to embed security ownership and "
            "decision making in workload teams."
        ),
        default=True,
    )


check_security_guardians_program._CHECK_ID = CHECK_ID
check_security_guardians_program._CHECK_NAME = CHECK_NAME
