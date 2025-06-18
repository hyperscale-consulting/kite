"""Check for performing Dynamic Application Security Testing (DAST)."""

from typing import Dict, Any

from kite.helpers import manual_check

CHECK_ID = "perform-dast"
CHECK_NAME = "Perform Dynamic Application Security Testing"


def check_perform_dast() -> Dict[str, Any]:
    """
    Check if DAST (Dynamic Application Security Testing) is used to detect potential
    runtime security issues.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that DAST (Dynamic Application Security Testing) is used "
        "to detect potential runtime security issues.\n\n"
        "Consider the following factors:\n"
        "- Is DAST integrated into the development pipeline?\n"
        "- Are DAST results reviewed and acted upon in a timely manner?\n"
        "- Are false positives managed and minimized?"
    )
    prompt = (
        "Is DAST (Dynamic Application Security Testing) used to detect potential "
        "runtime security issues?"
    )

    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "DAST is effectively used to detect potential runtime security issues."
        ),
        fail_message=(
            "DAST should be used to detect potential runtime security issues."
        ),
        default=True,
    )

    return result


check_perform_dast._CHECK_ID = CHECK_ID
check_perform_dast._CHECK_NAME = CHECK_NAME
