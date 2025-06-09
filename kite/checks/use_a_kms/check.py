"""Check for use of KMS with HSM protection."""

from typing import Dict, Any, List, Tuple

from kite.data import get_kms_keys
from kite.helpers import get_account_ids_in_scope, manual_check
from kite.config import Config


CHECK_ID = "use-a-kms"
CHECK_NAME = "Use a KMS"


def _format_keys_by_origin(
    keys: List[Dict[str, Any]], account: str, region: str
) -> Tuple[List[str], List[str]]:
    """
    Format KMS keys grouped by their origin.

    Args:
        keys: List of KMS key dictionaries
        account: AWS account ID
        region: AWS region

    Returns:
        Tuple of (hsm_keys, external_store_keys) where each is a list of
        formatted key strings
    """
    # Group keys by origin
    hsm_keys = []
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
        if origin in ["AWS_KMS", "EXTERNAL", "AWS_CLOUDHSM"]:
            hsm_keys.append(formatted_key)
        elif origin == "EXTERNAL_KEY_STORE":
            external_store_keys.append(formatted_key)

    return hsm_keys, external_store_keys


def check_use_a_kms() -> Dict[str, Any]:
    """
    Check if all keys are stored in a Key Management System using hardware
    security modules to protect keys.

    This check:
    1. Lists all KMS keys in each account and region
    2. Identifies keys protected by hardware security modules
    3. Identifies keys in external key stores
    4. Asks the user to verify that all keys are properly protected

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    config = Config.get()
    all_hsm_keys = []
    all_external_store_keys = []

    # Get all in-scope accounts
    accounts = get_account_ids_in_scope()

    # Check each account in each active region
    for account in accounts:
        for region in config.active_regions:
            # Get keys for this account and region
            keys = get_kms_keys(account, region)

            if keys:
                hsm_keys, external_store_keys = _format_keys_by_origin(
                    keys, account, region
                )
                all_hsm_keys.extend(hsm_keys)
                all_external_store_keys.extend(external_store_keys)

    # Format the output
    output = []
    if all_hsm_keys:
        output.append("\nAWS KMS keys protected by hardware security module:")
        output.extend(sorted(all_hsm_keys))

    if all_external_store_keys:
        output.append(
            "\nExternal key store keys (please verify these are protected by "
            "hardware security module):"
        )
        output.extend(sorted(all_external_store_keys))

    # Build the message
    message = (
        "This check verifies that all keys are stored in a Key Management System "
        "using hardware security modules to protect keys.\n\n"
        "This includes keys used by workloads to encrypt data, which should be "
        "envelope encrypted with a key that is stored in a HSM-backed KMS.\n\n"
        "Current KMS Keys:\n"
        + "\n".join(output)
        + "\n\nPlease verify that:\n"
        "- All keys used for data encryption are envelope encrypted with a key "
        "stored in a HSM-backed KMS\n"
        "- All external key stores use hardware security modules to protect keys"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are all keys stored in a Key Management System using hardware "
            "security modules to protect keys?"
        ),
        pass_message=(
            "All keys are stored in a Key Management System using hardware "
            "security modules to protect keys."
        ),
        fail_message=(
            "All keys should be stored in a Key Management System using hardware "
            "security modules to protect keys."
        ),
        default=True,
    )


check_use_a_kms._CHECK_ID = CHECK_ID
check_use_a_kms._CHECK_NAME = CHECK_NAME
