"""Check for pre-deployment of incident response tools."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "pre-deploy-tools"
CHECK_NAME = "Pre-deploy Incident Response Tools"


def check_pre_deploy_tools() -> dict[str, Any]:
    """
    Check if tools required to support incident response are deployed in advance.

    This check verifies that essential incident response tools are deployed and
    configured before an incident occurs, rather than being deployed reactively.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that essential incident response tools are deployed "
        "and configured before an incident occurs, rather than being deployed "
        "reactively.\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are tools required to support incident response (such as log "
            "analysis tools, forensic tools, monitoring systems) deployed "
            "and configured in advance of an incident?"
        ),
        pass_message=(
            "Essential incident response tools are deployed and configured "
            "in advance, enabling effective response when incidents occur."
        ),
        fail_message=(
            "Incident response tools are not pre-deployed. This can delay "
            "response times and reduce effectiveness during incidents."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_pre_deploy_tools._CHECK_ID = CHECK_ID
check_pre_deploy_tools._CHECK_NAME = CHECK_NAME
