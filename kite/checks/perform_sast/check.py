"""Check for performing Static Application Security Testing (SAST)."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "perform-sast"
CHECK_NAME = "Perform Static Application Security Testing"


def check_perform_sast() -> dict[str, Any]:
    """
    Check if SAST (Static Application Security Testing) is used to analyze source code
    for anomalous security patterns and provide indications for defect prone code.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that SAST (Static Application Security Testing) is used "
        "to analyze source code for anomalous security patterns and provide "
        "indications for defect prone code.\n\n"
        "Consider the following factors:\n"
        "- Is SAST integrated into the development pipeline?\n"
        "- Is SAST integrated into the developer IDEs?\n"
        "- Are SAST results reviewed and acted upon in a timely manner?\n"
        "- Are false positives managed and minimized?"
    )
    prompt = (
        "Is SAST (Static Application Security Testing) used to analyze source code "
        "for anomalous security patterns and provide indications for defect prone code?"
    )

    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "SAST is effectively used to analyze source code for security patterns "
            "and identify defect prone code."
        ),
        fail_message=(
            "SAST should be used to analyze source code for security patterns and "
            "identify defect prone code."
        ),
        default=True,
    )

    return result


check_perform_sast._CHECK_ID = CHECK_ID
check_perform_sast._CHECK_NAME = CHECK_NAME
