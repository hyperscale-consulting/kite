"""Check for definition of access requirements."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "define-access-requirements"
CHECK_NAME = "Define Access Requirements"


def check_define_access_requirements() -> Dict[str, Any]:
    """
    Check if there is a clear definition of who or what should have access to each
    resource or component.

    Returns:
        Dict containing the check results.
    """
    message = (
        "Is there a clear definition of who or what should have access to each "
        "resource or component?\n\n"
        "This could be in the form of a simple table similar to the following:\n\n"
        "| Who / what               | Resource / component                        | Access       |\n"  # noqa: E501
        "|--------------------------|---------------------------------------------|--------------|\n"  # noqa: E501
        "| MyApp ECS tasks          | All objects in the 'my-app-media' S3 bucket | read         |\n"  # noqa: E501
        "| MyApp ECS tasks          | my-app dynamodb table                       | read / write |\n"  # noqa: E501
        "| MyApp ECS task exec      | my-app/secret-key SM secret                 | read         |\n"  # noqa: E501
        "| MyApp secrets admin user | my-app/secret-key SM secret                 | read / write |\n"  # noqa: E501
        "|---------------------------------------------------------------------------------------|\n"  # noqa: E501
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=("Is there a clear definition of who or what should have access to "
                "each component?"),
        pass_message="Access requirements are clearly defined for each resource",
        fail_message="Access requirements should be clearly defined for each resource",
        default=True,
    )


# Attach the check ID and name to the function
check_define_access_requirements._CHECK_ID = CHECK_ID
check_define_access_requirements._CHECK_NAME = CHECK_NAME
