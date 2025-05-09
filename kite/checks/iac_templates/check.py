"""Check for standard security controls and configurations defined using IaC templates."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "iac-templates"
CHECK_NAME = "IaC Templates"


def check_iac_templates() -> Dict[str, Any]:
    """
    Check if standard security controls and configurations are defined using
    Infrastructure as Code (IaC) templates.

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
        "This check verifies that standard security controls and configurations "
        "are defined using Infrastructure as Code (IaC) templates.\n\n"
        "Consider the following factors:\n"
        "- Are standard security controls defined using IaC templates?\n"
        "- Are standard configurations defined using IaC templates?\n"
        "- Are IaC templates used consistently across the organization?"
    )
    prompt = (
        "Are standard security controls and configurations defined using "
        "Infrastructure as Code (IaC) templates?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Standard security controls and configurations are defined using "
            "Infrastructure as Code (IaC) templates."
        ),
        fail_message=(
            "Standard security controls and configurations should be defined using "
            "Infrastructure as Code (IaC) templates."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_iac_templates._CHECK_ID = CHECK_ID
check_iac_templates._CHECK_NAME = CHECK_NAME
