"""Check for automated patch management."""

from typing import Dict, Any, List

from kite.data import get_ec2_instances, get_maintenance_windows
from kite.config import Config
from kite.helpers import get_account_ids_in_scope, manual_check


CHECK_ID = "automate-patch-management"
CHECK_NAME = "Automate Patch Management"


def _format_maintenance_window_details(maintenance_windows: List[Dict[str, Any]]) -> str:
    """
    Format maintenance window details for display.

    Args:
        maintenance_windows: List of maintenance windows

    Returns:
        Formatted string with maintenance window details
    """
    if not maintenance_windows:
        return "  No maintenance windows found.\n"

    details = ""
    for mw in maintenance_windows:
        # Only show enabled maintenance windows
        if not mw.get("Enabled", False):
            continue

        details += f"  Maintenance Window: {mw.get('Name', 'Unknown')}\n"
        details += f"    Window ID: {mw.get('WindowId', 'Unknown')}\n"
        details += f"    Schedule: {mw.get('Schedule', 'Unknown')}\n"
        details += f"    Duration: {mw.get('Duration', 'Unknown')} hours\n"
        details += f"    Cutoff: {mw.get('Cutoff', 'Unknown')} hours\n"

        # Show targets
        targets = mw.get('Targets', [])
        if targets:
            details += f"    Targets ({len(targets)}):\n"
            for target in targets:
                details += f"      - Name: {target.get('Name', 'Unknown')}\n"
                details += f"        Targets: {target.get('Targets', [])}\n"
        else:
            details += "    Targets: None\n"

        # Show tasks
        tasks = mw.get('Tasks', [])
        if tasks:
            details += f"    Tasks ({len(tasks)}):\n"
            for task in tasks:
                details += f"      - Name: {task.get('Name', 'Unknown')}\n"
                details += f"        Type: {task.get('Type', 'Unknown')}\n"
                details += f"        Task ARN: {task.get('TaskArn', 'Unknown')}\n"
        else:
            details += "    Tasks: None\n"

        details += "\n"

    return details


def check_automate_patch_management() -> Dict[str, Any]:
    """
    Check if automatic patch management is implemented for EC2 instances.

    This check:
    1. Identifies accounts and regions containing EC2 instances
    2. Displays maintenance window details for those accounts and regions
    3. Prompts the user to confirm if automatic patch management is implemented

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
                - accounts_with_ec2: Dict mapping account IDs to regions with EC2 instances
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

    accounts_with_ec2 = {}
    has_ec2_instances = False
    config = Config.get()

    # Check each account and region for EC2 instances
    for account_id in account_ids:
        regions_with_ec2 = {}
        for region in config.active_regions:
            instances = get_ec2_instances(account_id, region)
            if instances:
                has_ec2_instances = True
                regions_with_ec2[region] = instances
        if regions_with_ec2:
            accounts_with_ec2[account_id] = regions_with_ec2

    # Build message
    message = "Automated Patch Management Check:\n\n"

    if not has_ec2_instances:
        message += "No EC2 instances found in any account. This check is not applicable.\n"
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": message,
                "accounts_with_ec2": accounts_with_ec2,
            },
        }

    message += "EC2 instances found in the following accounts and regions:\n\n"

    # Show EC2 instances and maintenance windows for each account
    for account_id, regions in accounts_with_ec2.items():
        message += f"Account: {account_id}\n"
        for region, instances in regions.items():
            message += f"  Region: {region}\n"
            message += f"  EC2 Instances: {len(instances)}\n"
            maintenance_windows = get_maintenance_windows(account_id, region)
            message += "  Maintenance Windows:\n"
            message += _format_maintenance_window_details(maintenance_windows)
        message += "\n"

    message += (
        "Please review the above maintenance window details and confirm that "
        "automatic patch management is implemented for EC2 instances\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is automatic patch management implemented for EC2 instances using "
            "AWS Systems Manager Maintenance Windows?"
        ),
        pass_message=(
            "Automatic patch management is implemented for EC2 instances using "
            "AWS Systems Manager Maintenance Windows."
        ),
        fail_message=(
            "Automatic patch management should be implemented for EC2 instances "
            "using AWS Systems Manager Maintenance Windows."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_automate_patch_management._CHECK_ID = CHECK_ID
check_automate_patch_management._CHECK_NAME = CHECK_NAME
