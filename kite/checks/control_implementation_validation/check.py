"""Check for control implementation validation."""

from kite.helpers import manual_check

CHECK_ID = "control-implementation-validation"
CHECK_NAME = "Control Implementation Validation"


def check_control_implementation_validation():
    """Check if security controls are implemented and enforced through automation and
    policy and continually evaluated for their effectiveness in achieving objectives.


    Returns:
        dict: A dictionary containing the check results.
    """
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=(
            "This check verifies that security controls are implemented and enforced "
            "through automation and policy and continually evaluated for their "
            "effectiveness in achieving objectives.\n\n"
            "Consider the following factors:\n"
            "- Are SCPs, resource policies, role trust policies, and other "
            "guardrails used to prevent non-compliant resource configurations?\n"
            "- Are Security Hub standards and AWS Config conformance packs used to "
            "track conformance?\n"
            "- Is evidence of effectiveness at both a point in time and over a period "
            "of time readily reportable to auditors?"
        ),
        prompt=(
            "Are security controls implemented and enforced through automation and "
            "policy and continually evaluated for their effectiveness?"
        ),
        pass_message=(
            "Security controls are implemented and enforced through automation and "
            "policy and continually evaluated for their effectiveness."
        ),
        fail_message=(
            "Security controls are not fully implemented, enforced, or evaluated "
            "for effectiveness."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_control_implementation_validation._CHECK_ID = CHECK_ID
check_control_implementation_validation._CHECK_NAME = CHECK_NAME
