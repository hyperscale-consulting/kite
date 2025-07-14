"""Check for code reviews to detect security vulnerabilities."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "conduct-code-reviews"
CHECK_NAME = "Conduct Code Reviews"


def check_conduct_code_reviews() -> dict[str, Any]:
    """
    Check if code reviews are used to detect security vulnerabilities in production
    code.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    # Define the message and prompts
    message = (
        "This check verifies that code reviews are used to detect security "
        "vulnerabilities in production code.\n\n"
        "Consider the following factors:\n"
        "- Are code reviews mandatory before code is merged to production?\n"
        "- Do code reviews include security-focused checks?\n"
        "- Are reviewers trained to identify common security vulnerabilities?\n"
        "- Are code review checklists and guidelines used?"
    )
    prompt = (
        "Are code reviews used to detect security vulnerabilities in production code?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Code reviews are used to detect security vulnerabilities in production "
            "code."
        ),
        fail_message=(
            "Code reviews should be used to detect security vulnerabilities in "
            "production code."
        ),
        default=True,
    )

    return result


check_conduct_code_reviews._CHECK_ID = CHECK_ID
check_conduct_code_reviews._CHECK_NAME = CHECK_NAME
