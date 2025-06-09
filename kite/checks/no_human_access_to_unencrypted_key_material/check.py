"""Check for prevention of human access to unencrypted key material."""

from typing import Dict, Any, List

from kite.data import get_kms_keys
from kite.helpers import get_account_ids_in_scope, manual_check
from kite.config import Config


CHECK_ID = "no-human-access-to-unencrypted-key-material"
CHECK_NAME = "No Human Access to Unencrypted Key Material"


def _format_external_keys(
    keys: List[Dict[str, Any]], account: str, region: str
) -> tuple[List[str], List[str]]:
    """
    Format KMS keys that could potentially be accessed in unencrypted form.

    Args:
        keys: List of KMS key dictionaries
        account: AWS account ID
        region: AWS region

    Returns:
        Tuple of (external_keys, external_store_keys) where each is a list of
        formatted key strings
    """
    external_keys = []
    external_store_keys = []

    for key in keys:
        key_id = key.get("KeyId")
        if not key_id:
            continue

        metadata = key.get("Metadata", {})
        if metadata.get("KeyManager") != "CUSTOMER":
            continue

        formatted_key = f"  - {key_id} ({account}/{region})"
        origin = metadata.get("Origin")
        if origin == "EXTERNAL":
            external_keys.append(formatted_key)
        elif origin == "EXTERNAL_KEY_STORE":
            external_store_keys.append(formatted_key)

    return external_keys, external_store_keys


def check_no_human_access_to_unencrypted_key_material() -> Dict[str, Any]:
    """
    Check if human access to unencrypted key material is prevented.

    This check:
    1. Lists all KMS keys that could potentially be accessed in unencrypted form
    2. Automatically fails if any EXTERNAL keys are found (as they require human
       access during key generation)
    3. Asks the user to verify controls for any EXTERNAL_KEY_STORE keys
    4. Asks the user to verify that data keys used by workloads are properly
       protected and never accessed in unencrypted form

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    config = Config.get()
    all_external_keys = []
    all_external_store_keys = []

    # Get all in-scope accounts
    accounts = get_account_ids_in_scope()

    # Check each account in each active region
    for account in accounts:
        for region in config.active_regions:
            # Get keys for this account and region
            keys = get_kms_keys(account, region)

            if keys:
                external_keys, external_store_keys = _format_external_keys(
                    keys, account, region
                )
                all_external_keys.extend(external_keys)
                all_external_store_keys.extend(external_store_keys)

    # If we found any EXTERNAL keys, automatically fail
    if all_external_keys:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "The following KMS keys are of type EXTERNAL, which requires "
                    "human access to unencrypted key material during key "
                    "generation:\n"
                    + "\n".join(sorted(all_external_keys))
                    + "\n\nThese keys should be replaced with AWS_KMS or "
                    "AWS_CLOUDHSM keys to prevent human access to unencrypted "
                    "key material."
                )
            },
        }

    # Build the message based on what we found
    message_parts = [
        "This check verifies that human access to unencrypted key material is "
        "prevented.\n\n"
    ]

    if all_external_store_keys:
        message_parts.extend([
            "The following KMS keys are in external key stores. Please verify "
            "that appropriate controls are in place to prevent human access to "
            "unencrypted key material:\n"
            + "\n".join(sorted(all_external_store_keys))
            + "\n\n"
        ])

    message_parts.extend([
        "Please verify that:\n"
        "- All data keys used by workloads are envelope encrypted with a key "
        "stored in a HSM-backed KMS\n"
        "- No human access to unencrypted data keys is possible\n"
        "- Data keys are only used in memory and never stored in unencrypted form"
    ])

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message="".join(message_parts),
        prompt=(
            "Is human access to unencrypted key material prevented for all keys, "
            "including data keys used by workloads?"
        ),
        pass_message=(
            "Human access to unencrypted key material is prevented for all keys, "
            "including data keys used by workloads."
        ),
        fail_message=(
            "Human access to unencrypted key material should be prevented for all "
            "keys, including data keys used by workloads."
        ),
        default=True,
    )


check_no_human_access_to_unencrypted_key_material._CHECK_ID = CHECK_ID
check_no_human_access_to_unencrypted_key_material._CHECK_NAME = CHECK_NAME
