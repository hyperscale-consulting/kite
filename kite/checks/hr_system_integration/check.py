"""Check for HR system integration with identity provider."""

from typing import Any

from botocore.exceptions import ClientError

from kite.data import get_oidc_providers
from kite.data import get_saml_providers
from kite.helpers import is_identity_center_enabled
from kite.helpers import manual_check

CHECK_ID = "hr-idp-integration"
CHECK_NAME = "HR / IdP Integration"


def check_hr_system_integration() -> dict[str, Any]:
    """
    Check if the organization's HR systems are integrated with the identity provider
    to automatically synchronize personnel changes.

    This check:
    1. Gathers information about SAML and OIDC providers
    2. Checks if Identity Center is enabled
    3. Asks the user if HR systems are integrated with the identity provider

    Returns:
        Dict containing the check results.
    """
    # Track if we encountered any errors
    error_message = None

    # Gather information about sign-in mechanisms
    try:
        saml_providers = get_saml_providers()
    except ClientError as e:
        saml_providers = []
        error_message = f"Error checking SAML providers: {str(e)}"

    try:
        oidc_providers = get_oidc_providers()
    except ClientError as e:
        oidc_providers = []
        if error_message:
            error_message += f"\nError checking OIDC providers: {str(e)}"
        else:
            error_message = f"Error checking OIDC providers: {str(e)}"

    try:
        identity_center_enabled = is_identity_center_enabled()
    except ClientError as e:
        identity_center_enabled = False
        if error_message:
            error_message += f"\nError checking Identity Center status: {str(e)}"
        else:
            error_message = f"Error checking Identity Center status: {str(e)}"

    # If we encountered any errors, return an ERROR status
    if error_message:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {"message": error_message},
        }

    # Build the context message
    context_message = "Current IdPs:\n\n"

    if saml_providers:
        context_message += "SAML Providers:\n"
        for provider in saml_providers:
            context_message += f"- {provider['Arn']}\n"
            if "ValidUntil" in provider:
                context_message += f"  Valid until: {provider['ValidUntil']}\n"
    else:
        context_message += "No SAML providers configured\n"

    context_message += "\n"

    if oidc_providers:
        context_message += "OIDC Providers:\n"
        for provider in oidc_providers:
            context_message += f"- {provider['Arn']}\n"
            if "Url" in provider:
                context_message += f"  URL: {provider['Url']}\n"
    else:
        context_message += "No OIDC providers configured\n"

    context_message += "\n"
    context_message += (
        f"Identity Center enabled: {'Yes' if identity_center_enabled else 'No'}\n"
    )

    context_message += "\n"
    context_message += (
        "This check verifies that your HR systems are integrated with your "
        "identity provider to automatically synchronize personnel changes.\n\n"
        "Consider the following factors:\n"
        "- Are joiners automatically provisioned with appropriate access?\n"
        "- Are leavers automatically deprovisioned?\n"
        "- Are role changes automatically reflected in access permissions?\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=context_message,
        prompt=(
            "Are your HR systems integrated with your identity provider to "
            "automatically synchronize personnel changes?"
        ),
        pass_message=(
            "HR systems are integrated with the identity provider to automatically "
            "synchronize personnel changes"
        ),
        fail_message=(
            "HR systems should be integrated with the identity provider to "
            "automatically synchronize personnel changes"
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_hr_system_integration._CHECK_ID = CHECK_ID
check_hr_system_integration._CHECK_NAME = CHECK_NAME
