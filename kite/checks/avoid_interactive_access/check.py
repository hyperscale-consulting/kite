"""Check for avoiding interactive access in production environments."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "avoid-interactive-access"
CHECK_NAME = "Avoid Interactive Access"


def check_avoid_interactive_access() -> Dict[str, Any]:
    """
    Check if automated mechanisms are used instead of interactive access for
    production environments.

    This check asks the user to confirm that automated mechanisms such as Systems
    Manager automations, runbooks, and run commands are used to automate and
    control activities performed on production environments rather than allowing
    interactive access.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that automated mechanisms are used instead of "
        "interactive access for production environments.\n\n"
        "Consider the following factors:\n"
        "- Are Systems Manager automations used for routine tasks?\n"
        "- Are Systems Manager runbooks used for complex operations?\n"
        "- Are Systems Manager run commands used for ad-hoc tasks?\n"
        "- Are IAM policies used to define who can perform these actions and "
        "the conditions under which they are permitted?\n"
        "- Are all administrative tasks automated where possible?\n"
        "- Are these automations tested thoroughly in non-production environments?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are automated mechanisms such as Systems Manager automations, "
            "runbooks, and run commands used to automate and control activities "
            "performed on production environments rather than relying on "
            "interactive access?"
        ),
        pass_message=(
            "Automated mechanisms are used to control activities in production "
            "environments, minimizing interactive access."
        ),
        fail_message=(
            "Automated mechanisms should be used to control activities in "
            "production environments, minimizing interactive access."
        ),
        default=True,
    )


check_avoid_interactive_access._CHECK_ID = CHECK_ID
check_avoid_interactive_access._CHECK_NAME = CHECK_NAME
