"""Check for incorporation of AWS control and compliance documentation."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "aws-control-documentation"
CHECK_NAME = "AWS Control Documentation"


def check_aws_control_documentation() -> dict[str, Any]:
    """
    Check if AWS control and compliance documentation is incorporated into control
    evaluation and verification procedures.

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
        "This check verifies that AWS control and compliance documentation is "
        "incorporated into control evaluation and verification procedures, thus "
        "taking advantage of AWS's built-in controls and the shared responsibility "
        "model."
    )
    prompt = (
        "Is AWS control and compliance documentation incorporated into control "
        "evaluation and verification procedures?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "AWS control and compliance documentation is incorporated into control "
            "evaluation and verification procedures."
        ),
        fail_message=(
            "AWS control and compliance documentation should be incorporated into "
            "control evaluation and verification procedures."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_aws_control_documentation._CHECK_ID = CHECK_ID
check_aws_control_documentation._CHECK_NAME = CHECK_NAME
