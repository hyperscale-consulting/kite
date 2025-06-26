"""Check for running regular security event simulations."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "run-simulations"
CHECK_NAME = "Run Security Event Simulations"


def check_run_simulations() -> Dict[str, Any]:
    """
    Check if regular simulations of real-world security event scenarios are run
    to exercise and evaluate incident response capabilities.

    This check verifies that organizations conduct regular simulations to test
    their incident response processes, tools, and team capabilities.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that regular simulations of real-world security "
        "event scenarios are conducted to exercise and evaluate incident "
        "response capabilities.\n\n"
        "Consider the following factors:\n"
        "- Are simulations conducted on a regular schedule (e.g., quarterly)?\n"
        "- Do simulations cover realistic threat scenarios?\n"
        "- Are different types of incidents simulated (e.g., data breach, "
        "ransomware, insider threat)?\n"
        "- Do simulations test both technical and procedural response capabilities?\n"
        "- Are lessons learned documented and incorporated into response plans?\n"
        "- Do simulations involve cross-functional teams?\n"
        "- Are simulations designed to test communication and escalation procedures?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Do you run regular simulations of real-world security event "
            "scenarios designed to exercise and evaluate incident response "
            "capabilities?"
        ),
        pass_message=(
            "Regular security event simulations are conducted to test and "
            "improve incident response capabilities."
        ),
        fail_message=(
            "Regular security event simulations should be conducted to test "
            "and validate incident response capabilities."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_run_simulations._CHECK_ID = CHECK_ID
check_run_simulations._CHECK_NAME = CHECK_NAME
