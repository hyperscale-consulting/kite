"""Check for evaluation of new AWS services."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "aws-service-evaluation"
CHECK_NAME = "AWS Service Evaluation"


def check_aws_service_evaluation() -> Dict[str, Any]:
    """
    Check if teams keep up to date with the launch of new AWS services and evaluate
    their potential for use.

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
        "This check verifies that teams keep up to date with the launch of new "
        "AWS services and evaluate their potential for use.\n\n"
        "Consider the following factors:\n"
        "- Do teams regularly review new AWS service launches?\n"
        "- Do teams evaluate the potential benefits of new services?\n"
        "- Do teams consider migrating to new services where appropriate?"
    )
    prompt = (
        "Do teams keep up to date with the launch of new AWS services and evaluate "
        "their potential for use?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Teams keep up to date with the launch of new AWS services and evaluate "
            "their potential for use."
        ),
        fail_message=(
            "Teams should keep up to date with the launch of new AWS services and "
            "evaluate their potential for use."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_aws_service_evaluation._CHECK_ID = CHECK_ID
check_aws_service_evaluation._CHECK_NAME = CHECK_NAME
