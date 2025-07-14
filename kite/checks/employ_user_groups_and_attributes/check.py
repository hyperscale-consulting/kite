"""Check for use of user groups and attributes."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "employ-user-groups-and-attributes"
CHECK_NAME = "Employ User Groups and Attributes"


def check_employ_user_groups_and_attributes() -> dict[str, Any]:
    """
    Manual check to confirm if permissions are defined according to user groups and
    attributes.

    Returns:
        Dict containing the check results.
    """

    # Build message for manual check
    message = (
        "IAM data has been saved to .kite/audit/{account_id}/ for review.\n\n"
        "Please review the files for each account:\n"
    )

    message += "\nConsider the following questions:\n"
    message += (
        "1. Are permissions defined and duplicated individually for users?\n"
        "2. Are groups defined at too high a level, granting overly broad "
        "permissions?\n"
        "3. Are groups too granular, creating duplication and confusion?\n"
        "4. Do groups have duplicate permissions where attributes could be "
        "used instead?\n"
        "5. Are groups based on function, rather than resource access?\n\n"
        "Tip: focus on users, groups, and roles that can be assumed by humans, "
        "and look for condition clauses that constrain access based on tags.\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=("Are permissions defined according to user groups and attributes?"),
        pass_message=(
            "Permissions are defined according to user groups and attributes"
        ),
        fail_message=(
            "Permissions should be defined according to user groups and attributes"
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_employ_user_groups_and_attributes._CHECK_ID = CHECK_ID
check_employ_user_groups_and_attributes._CHECK_NAME = CHECK_NAME
