"""Check for controls to prevent and detect secrets in source code."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "prevent-and-detect-secrets-in-source-code"
CHECK_NAME = "Prevent and Detect Secrets in Source Code"


def check_prevent_and_detect_secrets() -> Dict[str, Any]:
    """
    Check if there are controls in place to prevent and detect secrets in source code.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - info: str containing any additional information provided by the user
    """
    # Define the message and prompts
    message = (
        "This check verifies that there are controls in place to prevent and detect "
        "secrets in source code.\n\n"
        "Consider the following factors:\n"
        "- Are there pre-commit hooks or similar controls to prevent secrets from "
        "being committed?\n"
        "- Are there automated scans in CI/CD pipelines to detect secrets?\n"
        "- Are there tools like AWS CodeGuru or similar to detect secrets?\n"
        "- Are these controls consistently applied across all repositories?"
    )
    prompt = (
        "Are there controls in place to prevent and detect secrets in source code?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Controls are in place to prevent and detect secrets in source code."
        ),
        fail_message=(
            "Controls should be in place to prevent and detect secrets in source code."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_prevent_and_detect_secrets._CHECK_ID = CHECK_ID
check_prevent_and_detect_secrets._CHECK_NAME = CHECK_NAME
