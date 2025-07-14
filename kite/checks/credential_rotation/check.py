"""Check for credential rotation."""

from typing import Dict, Any

from kite.helpers import (
    get_prowler_output,
    manual_check,
)


CHECK_ID = "credential-rotation"
CHECK_NAME = "Credential Rotation"


def check_credential_rotation() -> Dict[str, Any]:
    """
    Check if long-term credentials are rotated regularly.

    This check:
    1. Checks prowler results for access key rotation (90 days)
    2. Checks prowler results for KMS key rotation
    3. Checks prowler results for Secrets Manager rotation
    4. Asks the user if long-term credentials are rotated regularly

    Returns:
        Dict containing the check results.
    """
    # Get all prowler results
    prowler_results = get_prowler_output()

    # Get results for specific checks
    access_key_results = prowler_results.get("iam_rotate_access_key_90_days", [])
    kms_results = prowler_results.get("kms_cmk_rotation_enabled", [])
    secrets_results = prowler_results.get(
        "secretsmanager_automatic_rotation_enabled", []
    )

    # Build the context message
    context_message = "Relevant Prowler checks:\n\n"

    # Track if we found any failures
    found_failures = False

    # Add access key rotation results
    failed_access_keys = [r for r in access_key_results if r.status == "FAIL"]
    if failed_access_keys:
        found_failures = True
        context_message += "Access Key Rotation (90 days) - Failed Checks:\n"
        for result in failed_access_keys:
            context_message += f"- {result.resource_uid}\n"
        context_message += "\n"
    else:
        context_message += "Access Key Rotation (90 days) - No failures found.\n\n"

    # Add KMS key rotation results
    failed_kms_keys = [r for r in kms_results if r.status == "FAIL"]
    if failed_kms_keys:
        found_failures = True
        context_message += "KMS Key Rotation - Failed Checks:\n"
        for result in failed_kms_keys:
            context_message += f"- {result.resource_uid}\n"
        context_message += "\n"
    else:
        context_message += "KMS Key Rotation - No failures found.\n\n"

    # Add Secrets Manager rotation results
    failed_secrets = [r for r in secrets_results if r.status == "FAIL"]
    if failed_secrets:
        found_failures = True
        context_message += "Secrets Manager Rotation - Failed Checks:\n"
        for result in failed_secrets:
            context_message += f"- {result.resource_uid}\n"
        context_message += "\n"
    else:
        context_message += "Secrets Manager Rotation - No failures found.\n\n"

    if not found_failures:
        context_message += "All credential rotation checks passed.\n\n"

    context_message += (
        "This check verifies that long-term credentials are rotated regularly.\n\n"
        "Consider the following factors:\n"
        "- Are access keys rotated at least every 90 days?\n"
        "- Are KMS keys rotated annually?\n"
        "- Are secrets rotated automatically?\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=context_message,
        prompt=("Are long-term credentials rotated regularly?"),
        pass_message=("Long-term credentials are rotated regularly"),
        fail_message=("Long-term credentials should be rotated regularly"),
        default=True,
    )


# Attach the check ID and name to the function
check_credential_rotation._CHECK_ID = CHECK_ID
check_credential_rotation._CHECK_NAME = CHECK_NAME
