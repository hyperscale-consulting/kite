"""Check that all delegated admins are trusted accounts."""

from typing import Dict, Any, List

from kite.data import get_delegated_admins
from kite.helpers import prompt_user_with_panel
from kite.organizations import DelegatedAdmin


CHECK_ID = "trusted-delegated-admins"
CHECK_NAME = "Trusted Delegated Admins"


def check_trusted_delegated_admins() -> Dict[str, Any]:
    """
    Check that all delegated admins are trusted accounts.

    This check lists all delegated admins for the organization and asks the user
    to confirm that all delegated admins are trusted accounts.

    Returns:
        Dict[str, Any]: A dictionary containing the check result with the following
            keys:
            - status: The status of the check ("PASS", "FAIL", or "ERROR")
            - message: A message describing the result
            - details: Additional details about the result
    """
    # Get all delegated admins
    delegated_admins = get_delegated_admins()
    if delegated_admins is None:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "message": "No delegated administrators data found. Please run 'kite collect' first.",
            "details": {},
        }

    # If there are no delegated admins, the check passes
    if not delegated_admins:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "message": "No delegated admins found.",
            "details": {},
        }

    services_by_admin: Dict[str, List[DelegatedAdmin]] = {}
    for admin in delegated_admins:
        if admin.id not in services_by_admin:
            services_by_admin[admin.id] = []
        services_by_admin[admin.id].append(admin.service_principal)

    # Collect all unique delegated admin accounts
    all_admins: Dict[str, DelegatedAdmin] = {}
    for admin in delegated_admins:
        if admin.id not in all_admins:
            all_admins[admin.id] = admin

    # Prepare the list of delegated admins for user confirmation
    admin_list = []
    message = "Delegated Administrators:\n\n"
    for admin_id, admin in all_admins.items():
        services = services_by_admin[admin_id]
        admin_list.append(
            {
                "id": admin_id,
                "name": admin.name,
                "email": admin.email,
                "services": services,
            }
        )
        message += f"Account: {admin.name} ({admin.id})\n"
        message += f"Email: {admin.email}\n"
        message += "Services:\n"
        for service in services:
            message += f"  - {service}\n"
        message += "\n"

    # Ask the user to confirm that all delegated admins are trusted
    is_trusted, _ = prompt_user_with_panel(
        check_name=CHECK_NAME,
        message=message,
        prompt="Are all of these delegated administrators trusted accounts?",
        default=True,
    )

    if is_trusted:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "message": "All delegated admins are trusted accounts.",
            "details": {
                "delegated_admins": admin_list,
            },
        }
    else:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "message": "Some delegated admins may not be trusted accounts.",
            "details": {
                "delegated_admins": admin_list,
            },
        }


# Attach the check ID and name to the function
check_trusted_delegated_admins._CHECK_ID = CHECK_ID
check_trusted_delegated_admins._CHECK_NAME = CHECK_NAME
