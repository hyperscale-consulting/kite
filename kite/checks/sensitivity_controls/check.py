"""Controls based on data sensitivity check."""

from kite.helpers import manual_check

CHECK_ID = "controls-implemented-based-on-sensitivity"
CHECK_NAME = "Controls implemented based on data sensitivity"


def check_controls_implemented_based_on_sensitivity() -> dict[str, object]:
    """Check if appropriate controls are implemented based on data sensitivity.

    This check verifies that appropriate controls are implemented based on data
    sensitivity levels.
    """

    message = (
        "This check verifies that appropriate controls are implemented based on data "
        "sensitivity levels.\n\n"
        "Consider the following:\n"
        "- Are access controls (IAM policies, SCPs) implemented based on data "
        "sensitivity?\n"
        "- Is encryption (at rest and in transit) configured according to data "
        "sensitivity requirements?\n"
        "- Are audit logs and monitoring configured appropriately for each "
        "sensitivity level?\n"
        "- Are data retention policies implemented based on sensitivity?\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        prompt=(
            "Are appropriate controls implemented based on data sensitivity levels "
            "as required by your data classification policy?"
        ),
        pass_message="Controls are applied based on data sensitivity level.",
        fail_message="Controls are not applied based on data sensitivity.",
        message=message,
        default=True,
    )
