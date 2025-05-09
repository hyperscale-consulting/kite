"""Check for Well-Defined Security Control Objectives."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "well-defined-control-objectives"
CHECK_NAME = "Well-Defined Control Objectives"


def check_well_defined_control_objectives() -> Dict[str, Any]:
    """
    Check if security control objectives are well-defined and aligned with
    compliance requirements.

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
        "This check verifies that security control objectives are well-defined and "
        "aligned with compliance requirements.\n\n"
        "Consider the following factors:\n"
        "Things to consider:\n"
        "- Are security control objectives documented?\n"
        "- Is a cybersecurity framework, such as NIST CSF, CIS, ISO 27001, Cyber "
        "Essentials etc. used as a basis for control objectives?\n"
        "- Are compliance requirements well understood - e.g. GDPR, PCI DSS, market "
        "expectations, etc. And are these aligned to the control objectives?\n"
    )
    prompt = (
        "Are security control objectives well-defined and aligned with compliance "
        "requirements?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Security control objectives are well-defined and aligned with "
            "compliance requirements."
        ),
        fail_message=(
            "Security control objectives need to be better defined or aligned with "
            "compliance requirements."
        ),
        default=True,
    )

    return result


# Attach the check ID and name to the function
check_well_defined_control_objectives._CHECK_ID = CHECK_ID
check_well_defined_control_objectives._CHECK_NAME = CHECK_NAME
