"""Check for evaluation and implementation of new security services."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "security-services-evaluation"
CHECK_NAME = "Security Services Evaluation"


def check_security_services_evaluation() -> Dict[str, Any]:
    """
    Check if teams evaluate and implement new security services and features regularly.


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
        "This check verifies that teams evaluate and implement new security "
        "services and features regularly.\n\n"
        "Consider the following factors:\n"
        "- How to teams keep up to date with new security services and features? For "
        "example, do they subscribe to AWS or partner security blogs?\n"
        "- How are teams within the organisation encouraged to stay on top of "
        "security services and features?\n"
        "- Are innovation / sandbox accounts available for teams to experiment with?"
    )
    prompt = (
        "Do teams evaluate and implement new security services and features "
        "regularly?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Teams regularly evaluate and implement new security services and "
            "features."
        ),
        fail_message=(
            "Teams should regularly evaluate and implement new security services "
            "and features."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_security_services_evaluation._CHECK_ID = CHECK_ID
check_security_services_evaluation._CHECK_NAME = CHECK_NAME
