"""Delegated admins for security services check module."""

from kite.data import get_delegated_admins
from kite.helpers import prompt_user_with_panel

CHECK_ID = "delegated-admin-for-security-services"
CHECK_NAME = "Delegated admin for security services"


def check_delegated_admins_security_services() -> dict:
    """
    Check if the delegated admins for security services are set to the security tooling account.

    This check verifies that the delegated administrators for key AWS security services
    (Security Hub, Inspector, Macie, Detective, and GuardDuty) are set to the security
    tooling (audit) account.

    Returns:
        A dictionary containing the finding for the Delegated Admins for Security
        Services check.
    """

    # List of security services to check
    security_services = [
        "securityhub.amazonaws.com",
        "inspector2.amazonaws.com",
        "macie.amazonaws.com",
        "detective.amazonaws.com",
        "guardduty.amazonaws.com",
    ]

    delegated_admins = get_delegated_admins()
    if delegated_admins is None:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {
                "message": "No delegated administrators data found. Please run 'kite collect' first.",
            },
        }

    # If no delegated admins at all, fail the check
    if not delegated_admins:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": "No delegated administrators found for any services.",
            },
        }

    admins_by_service = {}
    for admin in delegated_admins:
        if admin.service_principal in security_services:
            admins_by_service[admin.service_principal] = admin

    # Check each security service
    missing_services = []
    security_service_admins = {}

    for service in security_services:
        if service in admins_by_service:
            security_service_admins[service] = admins_by_service[service]
        else:
            missing_services.append(service)

    # If any security services are missing delegated admins, fail the check
    if missing_services:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "The following security services do not have delegated "
                    "administrators: "
                )
                + ", ".join(missing_services),
            },
        }

    # Format the delegated admins information for display
    admins_info = "Delegated Administrators for Security Services:\n"
    for service, admin in security_service_admins.items():
        admins_info += f"\n{service}: "
        admins_info += f"{admin.name} ({admin.id}) - {admin.email}\n"

    # Use prompt_user_with_panel to get the user's response
    is_security_account, _ = prompt_user_with_panel(
        check_name=CHECK_NAME,
        message=admins_info,
        prompt="Are the delegated administrators the security tooling account?",
        default=True,
    )

    if is_security_account:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "Delegated administrators for security services are set to the "
                    "security tooling account."
                ),
                "delegated_admins": {
                    service: {
                        "id": admin.id,
                        "name": admin.name,
                        "email": admin.email,
                    }
                    for service, admin in security_service_admins.items()
                },
            },
        }
    else:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "Delegated administrators for security services are not set to the "
                    "security tooling account."
                ),
                "delegated_admins": {
                    service: {
                        "id": admin.id,
                        "name": admin.name,
                        "email": admin.email,
                    }
                    for service, admin in security_service_admins.items()
                },
            },
        }


# Attach the check ID and name to the function
check_delegated_admins_security_services._CHECK_ID = CHECK_ID
check_delegated_admins_security_services._CHECK_NAME = CHECK_NAME
