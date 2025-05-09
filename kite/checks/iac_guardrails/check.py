"""Check for guardrails to detect and alert on misconfigurations in templates."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "iac-guardrails"
CHECK_NAME = "IaC Guardrails"


def check_iac_guardrails() -> Dict[str, Any]:
    """
    Check if guardrails are in place to detect and alert on misconfigurations in
    templates before deployment.


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
        "This check verifies that guardrails are in place to detect and alert on "
        "misconfigurations in templates before deployment (e.g. CloudFormation "
        "Guard, cfn-lint, cfn-nag, CloudFormation Hooks etc).\n\n"
        "Consider the following factors:\n"
        "- Are guardrails in place to detect misconfigurations?\n"
        "- Are guardrails in place to alert on misconfigurations?\n"
        "- Are guardrails used before deployment?"
    )
    prompt = (
        "Are guardrails in place to detect and alert on misconfigurations in "
        "templates before deployment (e.g. CloudFormation Guard, cfn-lint, cfn-nag, "
        "CloudFormation Hooks etc)?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Guardrails are in place to detect and alert on misconfigurations in "
            "templates before deployment."
        ),
        fail_message=(
            "Guardrails should be in place to detect and alert on misconfigurations "
            "in templates before deployment."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_iac_guardrails._CHECK_ID = CHECK_ID
check_iac_guardrails._CHECK_NAME = CHECK_NAME
