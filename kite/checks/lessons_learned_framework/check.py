"""Check for lessons learned framework."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "lessons-learned-framework"
CHECK_NAME = "Lessons Learned Framework"


def check_lessons_learned_framework() -> dict[str, Any]:
    """
    Check if a lessons learned framework is in place to help prevent incidents
    from recurring and improve incident response.

    This check verifies that organizations have a structured approach to
    capturing, analyzing, and applying lessons learned from security incidents.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that a lessons learned framework is in place to "
        "help prevent incidents from recurring and improve incident response.\n\n"
        "Consider the following factors:\n"
        "- Is there a formal process for capturing lessons learned after incidents?\n"
        "- Are root cause analyses conducted for security incidents?\n"
        "- Are lessons learned documented and shared with relevant teams?\n"
        "- Is there a process for implementing improvements based on lessons learned?\n"
        "- Are lessons learned incorporated into training and awareness programs?\n"
        "- Is there regular review and updating of incident response procedures "
        "based on lessons learned?\n"
        "- Are metrics tracked to measure the effectiveness of improvements?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is a lessons learned framework in place to help prevent incidents "
            "from recurring and improve incident response?"
        ),
        pass_message=(
            "A lessons learned framework is in place to capture and apply "
            "insights from incidents to prevent recurrence and improve response."
        ),
        fail_message=(
            "A lessons learned framework should be established to systematically "
            "capture and apply insights from incidents."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_lessons_learned_framework._CHECK_ID = CHECK_ID
check_lessons_learned_framework._CHECK_NAME = CHECK_NAME
