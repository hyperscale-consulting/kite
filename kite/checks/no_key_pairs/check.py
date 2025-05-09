"""Check for absence of EC2 key pairs."""

from typing import Dict, Any, List

from kite.helpers import get_account_key_pairs, get_account_ids_in_scope


CHECK_ID = "no-key-pairs"
CHECK_NAME = "No EC2 Key Pairs"


def check_no_key_pairs() -> Dict[str, Any]:
    """
    Check if any EC2 key pairs exist in any account.

    This check verifies that no EC2 key pairs exist in any account in scope.
    Using SSM Instance Connect is recommended instead of key pairs.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - accounts_with_key_pairs: List of dictionaries containing:
                    - account_id: str
                    - key_pairs: List of key pair names
    """
    try:
        # Get all account IDs in scope
        account_ids = get_account_ids_in_scope()

        # Track accounts with key pairs
        accounts_with_key_pairs: List[Dict[str, Any]] = []

        # Check each account
        for account_id in account_ids:
            # Get the key pairs
            key_pairs = get_account_key_pairs(account_id)

            if key_pairs:
                accounts_with_key_pairs.append({
                    "account_id": account_id,
                    "key_pairs": [kp["KeyName"] for kp in key_pairs]
                })

        # Determine if the check passed
        passed = len(accounts_with_key_pairs) == 0

        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS" if passed else "FAIL",
            "details": {
                "message": (
                    "No EC2 key pairs found in any accounts."
                    if passed
                    else (
                        f"EC2 key pairs found in {len(accounts_with_key_pairs)} "
                        "accounts."
                    )
                ),
                "accounts_with_key_pairs": accounts_with_key_pairs,
            },
        }

    except Exception as e:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {
                "message": f"Error checking for EC2 key pairs: {str(e)}",
            },
        }


# Attach the check ID and name to the function
check_no_key_pairs._CHECK_ID = CHECK_ID
check_no_key_pairs._CHECK_NAME = CHECK_NAME
