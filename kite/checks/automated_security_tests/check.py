"""Check for automated security tests."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "automated-security-tests"
CHECK_NAME = "Automated Security Tests"


def check_automated_security_tests() -> dict[str, Any]:
    """
    Check if automated unit and integration tests are used to verify the security
    properties of applications.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that automated unit and integration tests are used to "
        "verify the security properties of applications.\n\n"
        "Consider the following factors:\n"
        "- Are there automated tests for security-critical functionality?\n"
        "- Are there tests for authentication and authorization mechanisms?\n"
        "- Are there tests for input validation and sanitization?\n"
        "- Are there tests for secure configuration settings?\n"
        "- Are these tests integrated into the CI/CD pipeline?"
    )
    prompt = (
        "Are automated unit and integration tests used to verify the security "
        "properties of applications?"
    )

    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Automated unit and integration tests are used to verify the security "
            "properties of applications."
        ),
        fail_message=(
            "Automated unit and integration tests should be used to verify the "
            "security properties of applications."
        ),
        default=True,
    )

    return result


check_automated_security_tests._CHECK_ID = CHECK_ID
check_automated_security_tests._CHECK_NAME = CHECK_NAME
