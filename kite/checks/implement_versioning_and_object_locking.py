"""Check for S3 bucket versioning and object locking."""

from typing import Any

from kite.data import get_bucket_metadata
from kite.helpers import get_account_ids_in_scope
from kite.helpers import manual_check

CHECK_ID = "implement-versioning-and-object-locking"
CHECK_NAME = "Implement Versioning and Object Locking"


def _get_buckets_without_protection() -> dict[str, dict[str, list[dict[str, Any]]]]:
    """
    Get all S3 buckets that don't have both versioning and object locking enabled.

    Returns:
        Dict mapping account IDs to Dict mapping regions to lists of buckets
        without both versioning and object locking enabled.
    """
    buckets_without_protection = {}

    # Check each account
    for account_id in get_account_ids_in_scope():
        buckets = get_bucket_metadata(account_id)
        unprotected_buckets = []

        for bucket in buckets:
            # Check if versioning is enabled
            versioning = bucket.get("Versioning")
            is_versioned = versioning and versioning == "Enabled"

            # Check if object locking is enabled
            object_lock = bucket.get("ObjectLockConfiguration")
            is_locked = (
                object_lock and object_lock.get("ObjectLockEnabled") == "Enabled"
            )

            # If either versioning or object locking is not enabled, add to list
            if not (is_versioned and is_locked):
                unprotected_buckets.append(
                    {
                        "bucket": bucket,
                        "missing_versioning": not is_versioned,
                        "missing_object_lock": not is_locked,
                    }
                )

        if unprotected_buckets:
            buckets_without_protection[account_id] = unprotected_buckets

    return buckets_without_protection


def check_implement_versioning_and_object_locking() -> dict[str, Any]:
    """
    Check if S3 buckets have versioning and object locking enabled where appropriate.

    This check identifies S3 buckets that don't have both versioning and object
    locking enabled, and asks the user to confirm if these features should be
    implemented.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
                - buckets_without_protection: Dict mapping account IDs to Dict
                  mapping regions to lists of buckets without both versioning and
                  object locking enabled
    """
    # Get buckets without both versioning and object locking
    buckets_without_protection = _get_buckets_without_protection()

    # Build message
    message = "S3 Buckets Without Versioning and Object Locking:\n\n"

    if not buckets_without_protection:
        message += "All S3 buckets have both versioning and object locking enabled.\n"
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": message,
                "buckets_without_protection": buckets_without_protection,
            },
        }

    # If we have buckets without protection, show their details
    for account_id, buckets in buckets_without_protection.items():
        if buckets:
            message += f"Account: {account_id}\n"
            for bucket_info in buckets:
                bucket = bucket_info["bucket"]
                message += f"\n  Bucket: {bucket['Name']}\n"
                if bucket_info["missing_versioning"]:
                    message += "  - Versioning is not enabled\n"
                if bucket_info["missing_object_lock"]:
                    message += "  - Object Lock is not enabled\n"
            message += "\n"

    message += (
        "Please review the above and confirm that versioning and object locking are "
        "implemented where appropriate\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is versioning and object locking implemented on all S3 buckets where "
            "appropriate?"
        ),
        pass_message=(
            "Versioning and object locking are implemented on all S3 buckets where "
            "appropriate."
        ),
        fail_message=(
            "Versioning and object locking should be implemented on S3 buckets where "
            "appropriate."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_implement_versioning_and_object_locking._CHECK_ID = CHECK_ID
check_implement_versioning_and_object_locking._CHECK_NAME = CHECK_NAME
