"""Check for key rotation in line with defined crypto periods."""

from typing import Any

from kite.config import Config
from kite.data import get_kms_keys
from kite.helpers import get_account_ids_in_scope
from kite.helpers import manual_check

CHECK_ID = "rotate-encryption-keys"
CHECK_NAME = "Rotate Encryption Keys"


def _format_keys_by_rotation_status(
    keys: list[dict[str, Any]], account: str, region: str
) -> tuple[list[str], list[str]]:
    """
    Format KMS keys grouped by their rotation status.

    Args:
        keys: List of KMS key dictionaries
        account: AWS account ID
        region: AWS region

    Returns:
        Tuple of (enabled_keys, disabled_keys) where each is a list of
        formatted key strings
    """
    enabled_keys = []
    disabled_keys = []

    for key in keys:
        key_id = key.get("KeyId")
        if not key_id:
            continue

        metadata = key.get("Metadata", {})
        if metadata.get("KeyManager") != "CUSTOMER":
            continue

        formatted_key = f"  - {key_id} ({account}/{region})"
        rotation_status = key.get("RotationStatus", {})
        if rotation_status.get("RotationEnabled"):
            enabled_keys.append(formatted_key)
        else:
            disabled_keys.append(formatted_key)

    return enabled_keys, disabled_keys


def check_rotate_encryption_keys() -> dict[str, Any]:
    """
    Check if all encryption keys are rotated in line with a defined crypto period.

    This check:
    1. Lists all KMS keys in each account and region
    2. Shows which keys have rotation enabled
    3. Asks the user to confirm that all keys are rotated according to defined
       crypto periods

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    config = Config.get()
    all_enabled_keys = []
    all_disabled_keys = []

    # Get all in-scope accounts
    accounts = get_account_ids_in_scope()

    # Check each account in each active region
    for account in accounts:
        for region in config.active_regions:
            # Get keys for this account and region
            keys = get_kms_keys(account, region)

            if keys:
                enabled_keys, disabled_keys = _format_keys_by_rotation_status(
                    keys, account, region
                )
                all_enabled_keys.extend(enabled_keys)
                all_disabled_keys.extend(disabled_keys)

    # Build the message based on what we found
    message_parts = [
        "This check verifies that all encryption keys are rotated in line with "
        "defined crypto periods.\n\n"
    ]

    if all_enabled_keys:
        message_parts.extend(
            [
                "KMS keys with rotation enabled:\n"
                + "\n".join(sorted(all_enabled_keys))
                + "\n\n"
            ]
        )

    if all_disabled_keys:
        message_parts.extend(
            [
                "KMS keys with rotation disabled:\n"
                + "\n".join(sorted(all_disabled_keys))
                + "\n\n"
            ]
        )

    message_parts.extend(
        [
            "Please verify that:\n"
            "- All keys are rotated according to defined crypto periods\n"
            "- Rotation periods align with security requirements\n"
            "- Rotation is automated where possible\n"
            "- Consider any envelope encrypted data keys used by workloads."
        ]
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message="".join(message_parts),
        prompt=("Are all encryption keys rotated in line with defined crypto periods?"),
        pass_message=(
            "All encryption keys are rotated in line with defined crypto periods."
        ),
        fail_message=(
            "All encryption keys should be rotated in line with defined crypto periods."
        ),
        default=True,
    )


check_rotate_encryption_keys._CHECK_ID = CHECK_ID
check_rotate_encryption_keys._CHECK_NAME = CHECK_NAME
