"""Check for root credentials management enabled."""

from typing import Any

from kite.data import get_organization_features

CHECK_ID = "root-credentials-management-enabled"
CHECK_NAME = "Root Credentials Management Enabled"


def check_root_credentials_management_enabled() -> dict[str, Any]:
    """
    Check if root credentials management is enabled at the organizational level.

    This check verifies that the IAM organization feature for root credentials
    management is enabled.

    Returns:
        Dict containing the check result.
    """
    # Get the organization features
    features = get_organization_features()

    # Check if root credentials management is enabled
    if "RootCredentialsManagement" in features:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "Root credentials management is enabled at the "
                    "organizational level."
                )
            },
        }

    # If we get here, root credentials management is not enabled
    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": (
                "Root credentials management is not enabled at the "
                "organizational level. This feature helps prevent the use of "
                "root account credentials for day-to-day operations."
            )
        },
    }


# Attach the check ID and name to the function
check_root_credentials_management_enabled._CHECK_ID = CHECK_ID
check_root_credentials_management_enabled._CHECK_NAME = CHECK_NAME
