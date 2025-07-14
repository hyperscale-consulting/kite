"""Management account workloads check module."""

from typing import Any

from rich.console import Console

from kite.config import Config
from kite.data import get_mgmt_account_workload_resources
from kite.helpers import prompt_user_with_panel

console = Console()


CHECK_ID = "no-management-account-workloads"
CHECK_NAME = "No Management Account Workloads"


def check_management_account_workloads(config: Config = None) -> dict[str, Any]:
    """
    Check if there are workloads running in the management account.

    Args:
        config: The configuration object containing AWS credentials and settings.
               If not provided, it will be retrieved using Config.get().

    Returns:
        A dictionary containing the check results.
    """
    # Get the management account ID
    config = Config.get()

    mgmt_account_id = config.management_account_id

    # If no management account ID is provided, we can pass this check
    if not mgmt_account_id:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "No management account ID provided in config, skipping check."
                ),
            },
        }

    # Load the collected workload resources
    workload_resources = get_mgmt_account_workload_resources()
    if workload_resources is None:
        raise Exception("No workload resources data found. Run 'kite collect' first.")

    if not workload_resources.resources:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": ("No workload resources found in the management account."),
            },
        }

    # Initialize message with guidance
    message = (
        "This check evaluates if there are workloads running in the management account."
    )

    # Add assessment guidance
    message += "\nConsider the following factors for management account workloads:\n"
    message += "- Are there any workloads running in the management account?\n"
    message += (
        "- If so, are there valid reasons for these workloads to be in"
        " the management account?\n"
    )
    message += "- Could these workloads be moved to a dedicated workload account?\n"

    # Format workload resources for display
    formatted_resources = []
    for resource in workload_resources.resources:
        resource_str = f"{resource.resource_type}: {resource.resource_id}"
        if resource.region:
            resource_str += f" in {resource.region}"
        if resource.details:
            details_str = ", ".join(f"{k}={v}" for k, v in resource.details.items())
            resource_str += f" ({details_str})"
        formatted_resources.append(resource_str)

    # Add workload resources to the message if any were found
    if formatted_resources:
        message += (
            "\nThe following workload resources were found in the management account:\n"
        )
        for resource in formatted_resources:
            message += f"- {resource}\n"

    # Ask user to confirm management account workload status
    prompt = "Is the management account free of workload resources?"
    no_workloads, _ = prompt_user_with_panel(
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        default=False,
    )

    if no_workloads:
        success_msg = (
            "The management account is free of workload resources. "
            "This is the recommended configuration."
        )
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": success_msg,
            },
        }

    fail_msg = (
        "The management account contains workload resources. "
        "Consider moving these resources to a dedicated workload account."
    )
    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": fail_msg,
        },
    }


# Attach the check ID and name to the function
check_management_account_workloads._CHECK_ID = CHECK_ID
check_management_account_workloads._CHECK_NAME = CHECK_NAME
