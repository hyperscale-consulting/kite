"""Check for formal incident response plans."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "incident-response-plans"
CHECK_NAME = "Incident Response Plans"


def check_incident_response_plans() -> Dict[str, Any]:
    """
    Check if an incident response plan is captured in a formal document covering
    all required components.


    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that an incident response plan is captured in a "
        "formal document covering the following:\n"
        "- The goals and function of the incident response team\n"
        "- Incident response stakeholders and their roles when an incident occurs, "
        "including HR, Legal, Executive team, app owners, and developers\n"
        "- A communication plan\n"
        "- Backup communication methods\n"
        "- The phases of incident response and the high level actions to take in those phases\n"
        "- A process for classifying incident severity\n"
        "- Severity definitions and their impact on escalation procedures"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is an incident response plan captured in a formal document covering "
            "the goals and function of the incident response team, stakeholder "
            "roles, communication plans, backup communication methods, incident "
            "response phases, and severity classification with escalation "
            "procedures?"
        ),
        pass_message=(
            "A formal incident response plan exists covering all required components."
        ),
        fail_message=(
            "A formal incident response plan should exist covering all required "
            "components."
        ),
        default=True,
    )


check_incident_response_plans._CHECK_ID = CHECK_ID
check_incident_response_plans._CHECK_NAME = CHECK_NAME
