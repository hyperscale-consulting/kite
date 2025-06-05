"""Check for documented data classification scheme."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "documented-data-classification-scheme"
CHECK_NAME = "Documented Data Classification Scheme"


def check_documented_data_classification_scheme() -> Dict[str, Any]:
    """
    Check if there is a documented data classification scheme.

    This check verifies that there is a documented data classification scheme that
    describes:
    - Data handling requirements
    - Data lifecycle management
    - Backup requirements
    - Encryption policies
    - Access control requirements
    - Data destruction procedures
    - Access auditing requirements

    Returns:
        Dictionary containing check results
    """
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=(
            "This check verifies that there is a documented data classification "
            "scheme that describes the data classification levels and, for each level"
            " and for each state (at rest, in transit and in use), the controls that "
            "should be in place including:\n\n"
            "- Data handling requirements\n"
            "- Data lifecycle management\n"
            "- Backup requirements\n"
            "- Encryption policies\n"
            "- Access control requirements\n"
            "- Data destruction procedures\n"
            "- Access auditing requirements\n\n"
            "Consider the following factors:\n"
            "- Is the classification scheme comprehensive and covers all data types?\n"
            "- Are the requirements clear and actionable?\n"
            "- Is the scheme regularly reviewed and updated?"
        ),
        prompt=(
            "Is there a documented data classification scheme that describes "
            "handling requirements, lifecycle, backup, encryption policies, access "
            "control, destruction and auditing of access?"
        ),
        pass_message=(
            "A documented data classification scheme exists and covers all required "
            "aspects."
        ),
        fail_message=(
            "No documented data classification scheme exists or it does not cover "
            "all required aspects."
        ),
        default=True,
    )


check_documented_data_classification_scheme._CHECK_ID = CHECK_ID
check_documented_data_classification_scheme._CHECK_NAME = CHECK_NAME
