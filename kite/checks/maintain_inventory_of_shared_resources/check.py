"""Check for maintaining an inventory of shared resources."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "maintain-inventory-of-shared-resources"
CHECK_NAME = "Maintain Inventory of Shared Resources"


def check_maintain_inventory_of_shared_resources() -> dict[str, Any]:
    """
    Check if an inventory of shared resources is maintained.

    This check asks the user to confirm if they maintain an inventory of shared
    resources.

    Returns:
        A dictionary containing the check results.
    """
    message = (
        "Please confirm if you maintain an inventory of shared resources.\n\n"
        "This should include:\n"
        "1. S3 buckets\n"
        "2. SNS topics\n"
        "3. SQS queues\n"
        "4. Lambda functions\n"
        "5. KMS keys\n"
        "6. Other resources that are shared across accounts or with external "
        "parties\n\n"
        "The inventory should include:\n"
        "- What is shared\n"
        "- Who it is shared with\n"
        "- Why it is shared\n"
        "- When it was last reviewed\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt="Is an inventory of shared resources maintained?",
        pass_message="An inventory of shared resources is maintained",
        fail_message="An inventory of shared resources should be maintained",
        default=True,
    )


check_maintain_inventory_of_shared_resources._CHECK_ID = CHECK_ID
check_maintain_inventory_of_shared_resources._CHECK_NAME = CHECK_NAME
