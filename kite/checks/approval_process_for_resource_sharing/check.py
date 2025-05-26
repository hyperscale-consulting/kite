"""Check for approval process for resource sharing."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "approval-process-for-resource-sharing"
CHECK_NAME = "Approval Process for Resource Sharing"


def check_approval_process_for_resource_sharing() -> Dict[str, Any]:
    """
    Check if there is an approval process for resource sharing.

    This check asks the user to confirm if there is an approval process for
    sharing resources across accounts or with external parties.

    Returns:
        A dictionary containing the check results.
    """
    message = (
        "Please confirm if there is an approval process for resource sharing.\n\n"
        "The approval process should include:\n"
        "1. Who can approve resource sharing requests\n"
        "2. What information is required for approval\n"
        "3. How long approvals are valid for\n"
        "4. How approvals are documented\n"
        "5. How approvals are reviewed and revoked\n\n"
        "This applies to sharing of:\n"
        "- S3 buckets\n"
        "- SNS topics\n"
        "- SQS queues\n"
        "- Lambda functions\n"
        "- KMS keys\n"
        "- Other resources that can be shared"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt="Is there an approval process for resource sharing?",
        pass_message="An approval process for resource sharing exists",
        fail_message="An approval process for resource sharing should be established",
        default=True,
    )


check_approval_process_for_resource_sharing._CHECK_ID = CHECK_ID
check_approval_process_for_resource_sharing._CHECK_NAME = CHECK_NAME
