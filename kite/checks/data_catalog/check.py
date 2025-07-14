"""Check for data catalog."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "data-catalog"
CHECK_NAME = "Data Catalog"


def check_data_catalog() -> dict[str, Any]:
    """
    Check if there is an inventory of all data within the organization.

    This check verifies that there is a data catalog that includes:
    - Location of all data
    - Sensitivity level of data
    - Data ownership
    - Controls in place to protect the data

    Returns:
        Dictionary containing check results
    """
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=(
            "This check verifies that there is an inventory of all data within the "
            "organization that includes:\n\n"
            "- Location\n"
            "- Sensitivity level\n"
            "- Ownership\n"
            "- Retention period\n"
            "- Controls in place to protect the data\n\n"
            "Consider the following factors:\n"
            "- Is the data catalog comprehensive and up-to-date?\n"
            "- Are data owners clearly identified and accountable?\n"
            "- Are sensitivity levels consistently applied?\n"
            "- Are security controls documented and validated?"
        ),
        prompt=(
            "Is there an inventory of all data within the organization, including "
            "its location, sensitivity level, owner, and the controls in place to "
            "protect that data?"
        ),
        pass_message=(
            "A comprehensive data catalog exists and includes all required information."
        ),
        fail_message=(
            "No data catalog exists or it does not include all required information."
        ),
        default=True,
    )


check_data_catalog._CHECK_ID = CHECK_ID
check_data_catalog._CHECK_NAME = CHECK_NAME
