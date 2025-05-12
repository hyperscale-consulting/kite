"""Check for use of higher-level services."""

from typing import Dict, Any

from kite.helpers import get_account_ids_in_scope, manual_check
from kite.data import get_ec2_instances

CHECK_ID = "use-of-higher-level-services"
CHECK_NAME = "Use of Higher-Level Services"


def check_use_of_higher_level_services() -> Dict[str, Any]:
    """
    Check if higher-level AWS services are preferred over lower-level services like EC2.

    This check:
    1. Identifies EC2 instances in in-scope accounts using collected data
    2. If EC2 instances exist, prompts the user to confirm if higher-level managed
       services are favored over lower-level services
    3. If no EC2 instances exist, automatically passes as higher-level services
       are assumed to be preferred

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - ec2_instances: List of EC2 instances found (if any)
    """
    # Get in-scope account IDs
    account_ids = get_account_ids_in_scope()
    if not account_ids:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": "No accounts in scope found.",
            },
        }

    ec2_instances_by_account = {}

    # Get EC2 instances for each account from collected data
    for account_id in account_ids:
        instances = get_ec2_instances(account_id)
        if instances:
            ec2_instances_by_account[account_id] = instances

    # If no EC2 instances found, automatically pass
    if not ec2_instances_by_account:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "No EC2 instances found in in-scope accounts. "
                    "Higher-level services appear to be preferred."
                ),
            },
        }

    # Create message for manual check
    message = (
        "EC2 instances were found in your in-scope accounts. "
        "Consider the following factors:\n"
        "- Are higher-level managed services favored over lower-level "
        "services such as EC2?\n"
        "- Are the total costs and risks associated with securing "
        "lower-level services accounted for when making decisions?\n\n"
        "EC2 Instances Found:\n"
    )

    # Add EC2 instance details to message
    for account_id, instances in ec2_instances_by_account.items():
        for instance in instances:
            message += (
                f"- Instance {instance.instance_id} in account "
                f"{account_id} ({instance.region}) - "
                f"State: {instance.state}\n"
            )

    # Use manual_check to get the user's response
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are higher-level managed services favored over lower-level "
            "services such as EC2?"
        ),
        pass_message=(
            "Higher-level managed services are favored over lower-level "
            "services such as EC2."
        ),
        fail_message=(
            "Consider migrating workloads to higher-level managed services "
            "where possible."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_use_of_higher_level_services._CHECK_ID = CHECK_ID
check_use_of_higher_level_services._CHECK_NAME = CHECK_NAME
