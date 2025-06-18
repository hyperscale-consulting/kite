"""Check for training engineers on application security topics."""

from typing import Dict, Any

from kite.helpers import manual_check

CHECK_ID = "train-for-application-security"
CHECK_NAME = "Train for Application Security"


def check_train_for_application_security() -> Dict[str, Any]:
    """
    Check if engineers receive training on application security topics including threat
    modeling, secure coding, security testing, and secure deployment practices.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that engineers receive training on application security "
        "topics including threat modeling, secure coding, security testing, and secure "
        "deployment practices.\n\n"
        "Consider the following factors:\n"
        "- Do engineers receive training on threat modeling and risk assessment?\n"
        "- Is there training on secure coding practices and common vulnerabilities?\n"
        "- Are engineers trained on security testing techniques and tools?\n"
        "- Is there training on secure deployment practices and configuration?\n"
        "- Is the training regularly updated to cover new threats and best practices?\n"
        "- Are there mechanisms to verify the effectiveness of the training?"
    )
    prompt = (
        "Do engineers receive training on application security topics including threat "
        "modeling, secure coding, security testing, and secure deployment practices?"
    )

    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Engineers receive comprehensive training on application security topics "
            "including threat modeling, secure coding, security testing, and secure "
            "deployment practices."
        ),
        fail_message=(
            "Engineers should receive training on application security topics including "
            "threat modeling, secure coding, security testing, and secure deployment "
            "practices."
        ),
        default=True,
    )

    return result


check_train_for_application_security._CHECK_ID = CHECK_ID
check_train_for_application_security._CHECK_NAME = CHECK_NAME
