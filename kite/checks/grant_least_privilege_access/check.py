"""Check for least privilege access."""

import json
from typing import Any

from rich.console import Console

from kite.helpers import assume_role
from kite.helpers import get_account_ids_in_scope
from kite.helpers import manual_check

CHECK_ID = "NOT_USED_grant-least-privilege-access"
CHECK_NAME = "NOT_USED Grant Least Privilege Access"

console = Console()


def _get_role_usage(session, role_name: str) -> dict[str, Any]:
    """
    THIS CHECK IS NOT USED.

    May come back to it - but it takes too long to fetch all the unused actions
    and generates a lot of noise.

    Get service last accessed details for a role.

    Args:
        session: The boto3 session to use
        role_name: The name of the role to check

    Returns:
        Dict containing the role's usage details
    """
    iam_client = session.client("iam")

    # Get the role's ARN
    role = iam_client.get_role(RoleName=role_name)["Role"]
    role_arn = role["Arn"]

    # Get service last accessed details
    try:
        response = iam_client.generate_service_last_accessed_details(
            Arn=role_arn, Granularity="ACTION_LEVEL"
        )
        job_id = response["JobId"]

        # Wait for the job to complete
        while True:
            status = iam_client.get_service_last_accessed_details(JobId=job_id)
            if status["JobStatus"] == "COMPLETED":
                break
            elif status["JobStatus"] == "FAILED":
                return {
                    "error": "Failed to generate service last accessed details",
                    "role_name": role_name,
                    "role_arn": role_arn,
                }

        # Get the results
        details = iam_client.get_service_last_accessed_details(JobId=job_id)

        # Process the results
        unused_actions = []
        for service in details.get("ServicesLastAccessed", []):
            service_name = service["ServiceName"]
            for action in service.get("TrackedActionsLastAccessed", []):
                if not action.get("LastAccessedDate"):
                    unused_actions.append(
                        {
                            "service": service_name,
                            "action": action["ActionName"],
                        }
                    )

        return {
            "role_name": role_name,
            "role_arn": role_arn,
            "unused_actions": unused_actions,
        }

    except Exception as e:
        return {
            "error": str(e),
            "role_name": role_name,
            "role_arn": role_arn,
        }


def _save_role_usage(account_id: str, data: dict[str, Any]) -> str:
    """
    Save role usage data to a file in the .kite/audit directory.

    Args:
        account_id: The AWS account ID
        data: The role usage data to save

    Returns:
        The path to the saved file
    """
    # Create .kite/audit directory if it doesn't exist
    import os

    os.makedirs(".kite/audit", exist_ok=True)

    # Create account-specific directory
    account_dir = f".kite/audit/{account_id}"
    os.makedirs(account_dir, exist_ok=True)

    # Save data to file
    file_path = f"{account_dir}/role_usage.json"
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    return file_path


def check_grant_least_privilege_access() -> dict[str, Any]:
    """
    Check if least privilege access has been granted for users and workloads.

    This check:
    1. Gets all IAM roles in each in-scope account
    2. For each role, generates service last accessed details with ACTION_LEVEL granularity
    3. Identifies any actions that have not been accessed
    4. Saves the data to .kite/audit/{account_id}/role_usage.json
    5. Asks the user if least privilege access has been granted

    Returns:
        Dict containing the check results.
    """
    try:
        # Get in-scope accounts
        account_ids = get_account_ids_in_scope()

        # Track saved files for each account
        saved_files = {}

        # Analyze role usage for each account
        for account_id in account_ids:
            try:
                console.print(
                    f"\n[bold blue]Analyzing IAM roles for account {account_id}...[/]"
                )

                # Assume role in the account
                session = assume_role(account_id)

                # Get all roles
                iam_client = session.client("iam")
                roles = []
                paginator = iam_client.get_paginator("list_roles")
                for page in paginator.paginate():
                    roles.extend(page["Roles"])

                # Get usage details for each role
                role_usage = {}
                for role in roles:
                    console.print(f"  [yellow]Analyzing role {role['RoleName']}...[/]")
                    role_usage[role["RoleName"]] = _get_role_usage(
                        session, role["RoleName"]
                    )

                # Save the data
                file_path = _save_role_usage(account_id, role_usage)
                saved_files[account_id] = file_path
                console.print(f"  [green]✓ Saved role usage data to {file_path}[/]")

                console.print(
                    f"[bold green]✓ Completed analyzing IAM roles for account "
                    f"{account_id}[/]"
                )
            except Exception as e:
                return {
                    "check_id": CHECK_ID,
                    "check_name": CHECK_NAME,
                    "status": "ERROR",
                    "details": {
                        "message": (
                            f"Error analyzing IAM roles for account {account_id}: "
                            f"{str(e)}"
                        ),
                    },
                }

        # Build message for manual check
        message = (
            "IAM role usage data has been saved to .kite/audit/{account_id}/ "
            "role_usage.json for review.\n\n"
            "Please review the following files for each account:\n"
        )

        for account_id, file_path in saved_files.items():
            message += f"\nAccount {account_id}:\n"
            message += f"- Role usage: {file_path}\n"

        message += "\nConsider the following questions:\n"
        message += (
            "1. Are there any unused permissions that can be removed?\n"
            "2. Are permissions granted at the most granular level possible?\n"
            "3. Are there any overly permissive policies that should be restricted?\n"
            "4. Are there any roles with unused actions that should be reviewed?\n"
            "5. Are there any roles that could be consolidated or removed?\n"
        )

        return manual_check(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            message=message,
            prompt=("Has least privilege access been granted for users and workloads?"),
            pass_message=(
                "Least privilege access has been granted for users and workloads"
            ),
            fail_message=(
                "Least privilege access should be granted for users and workloads"
            ),
            default=True,
        )

    except Exception as e:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {
                "message": f"Error checking least privilege access: {str(e)}",
            },
        }


# Attach the check ID and name to the function
check_grant_least_privilege_access._CHECK_ID = CHECK_ID
check_grant_least_privilege_access._CHECK_NAME = CHECK_NAME
