"""Check for accurate account contact details."""

from typing import Dict, Any

from kite.config import Config
from kite.helpers import (
    get_account_ids_in_scope,
    manual_check,
)
from kite.data import get_organization_features


CHECK_ID = "accurate-account-contact-details"
CHECK_NAME = "Accurate Account Contact Details"


def check_accurate_account_contact_details() -> Dict[str, Any]:
    """
    Check if account contact details are accurate and secure.

    This check verifies that:
    1. Root credentials management is enabled at the organizational level
    2. If enabled, only the management account contact details need to be verified
    3. If not enabled, all account contact details need to be verified

    This is a manual check with automated support to determine which accounts
    need to be checked.

    Returns:
        Dict containing the check result.
    """
    try:
        # Get the organization features
        features = get_organization_features()
        root_credentials_managed = "RootCredentialsManagement" in features

        # Get the management account ID from the config
        config = Config.get()
        management_account_id = config.management_account_id

        # Determine which accounts need to be checked
        if root_credentials_managed:
            if not management_account_id:
                return {
                    "check_id": CHECK_ID,
                    "check_name": CHECK_NAME,
                    "status": "ERROR",
                    "details": {
                        "message": (
                            "Root credentials management is enabled, but management "
                            "account ID could not be determined."
                        )
                    },
                }

            message = (
                "Root credentials management is enabled at the org level. "
                "Please verify the contact details for the management account only.\n\n"
                "Consider the following factors:\n"
                "- Are contact details accurate and up-to-date?\n"
                "- Is the email address on a corporate domain and a distribution list "
                "locked down to appropriate users?\n"
                "- Is the phone number a secure phone dedicated for this purpose?"
            )

            return manual_check(
                check_id=CHECK_ID,
                check_name=CHECK_NAME,
                message=message,
                prompt=(
                    "Are the contact details for the management account accurate "
                    "and secure?"
                ),
                pass_message=(
                    "Contact details for the management account are accurate and secure."
                ),
                fail_message=(
                    "Contact details for the management account need improvement."
                ),
                default=True,
            )

        else:
            # Check all accounts in scope
            get_account_ids_in_scope()  # Get accounts in scope for context

            message = (
                "Root credentials management is not enabled at the org level. "
                "Please verify the contact details for all accounts in scope.\n\n"
                "Consider the following factors:\n"
                "- Are contact details accurate and up-to-date?\n"
                "- Is the email address on a corporate domain and a distribution list "
                "  locked down to appropriate users?\n"
                "- Is the phone number a secure phone dedicated for this purpose?"
            )

            return manual_check(
                check_id=CHECK_ID,
                check_name=CHECK_NAME,
                message=message,
                prompt=(
                    "Are the contact details for all accounts accurate and secure?"
                ),
                pass_message=(
                    "Contact details for all accounts are accurate and secure."
                ),
                fail_message=("Contact details for some accounts need improvement."),
                default=True,
            )

    except Exception as e:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {
                "message": f"Error checking account contact details: {str(e)}",
            },
        }


# Attach the check ID and name to the function
check_accurate_account_contact_details._CHECK_ID = CHECK_ID
check_accurate_account_contact_details._CHECK_NAME = CHECK_NAME
