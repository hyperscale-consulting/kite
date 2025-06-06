"""Check for automated S3 data retention."""

from typing import Dict, Any, List
from collections import defaultdict

from kite.data import get_bucket_metadata
from kite.helpers import get_account_ids_in_scope, manual_check
from kite.config import Config


CHECK_ID = "automate-s3-data-retention"
CHECK_NAME = "Automate S3 Data Retention"


def _format_buckets_by_retention(buckets: List[Dict[str, Any]]) -> str:
    """
    Format buckets grouped by their retention period.

    Args:
        buckets: List of bucket dictionaries

    Returns:
        Formatted string showing buckets grouped by retention period
    """
    # Group buckets by retention period
    retention_groups = defaultdict(list)
    for bucket in buckets:
        name = bucket.get("Name")
        if not name:
            continue

        # Find the shortest expiration period in lifecycle rules
        retention = None
        lifecycle_rules = bucket.get("LifecycleRules")
        if lifecycle_rules is not None:  # Check if LifecycleRules exists
            for rule in lifecycle_rules:
                if "Expiration" in rule and "Days" in rule["Expiration"]:
                    days = rule["Expiration"]["Days"]
                    if retention is None or days < retention:
                        retention = days

        retention = retention if retention is not None else "Never Expire"
        retention_groups[str(retention)].append(name)

    # Format the output
    output = []
    # Sort by retention period, handling "Never Expire" specially
    sorted_retentions = sorted(
        retention_groups.keys(),
        key=lambda x: float("inf") if x == "Never Expire" else float(x),
    )
    for retention in sorted_retentions:
        buckets = retention_groups[retention]
        output.append(f"\nRetention (days): {retention}")
        for bucket in sorted(buckets):
            output.append(f"  - {bucket}")

    return "\n".join(output)


def check_automate_s3_data_retention() -> Dict[str, Any]:
    """
    Check if S3 lifecycle policies are used consistently to automatically delete
    data stored in S3 as it reaches the end of its defined retention period.

    This check:
    1. Shows all S3 buckets grouped by their retention period
    2. Asks the user to confirm if S3 lifecycle policies are used consistently

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    config = Config.get()
    buckets_by_retention = []

    # Get all in-scope accounts
    accounts = get_account_ids_in_scope()

    # Check each account in each active region
    for account in accounts:
        # Get buckets for this account and region
        buckets = get_bucket_metadata(account)

        if buckets:
            buckets_by_retention.append(
                f"\nAccount: {account} " + _format_buckets_by_retention(buckets)
            )

    # Build the message
    message = (
        "This check verifies that S3 lifecycle policies are used consistently "
        "to automatically delete data stored in S3 as it reaches the end of "
        "its defined retention period.\n\n"
        "Current S3 Buckets:\n"
        + "\n".join(buckets_by_retention)
        + "\n\nPlease review the retention periods above and consider:\n"
        "- Are S3 lifecycle policies used consistently across all buckets?\n"
        "- Are retention periods appropriate for the data stored in each bucket?\n"
        "- Is data automatically deleted when it reaches the end of its retention period?"
    )

    # Use manual_check to get user confirmation
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are S3 lifecycle policies used consistently to automatically delete "
            "data stored in S3 as it reaches the end of its defined retention "
            "period?"
        ),
        pass_message=(
            "S3 lifecycle policies are used consistently to automatically delete "
            "data stored in S3 as it reaches the end of its defined retention "
            "period."
        ),
        fail_message=(
            "S3 lifecycle policies should be used consistently to automatically "
            "delete data stored in S3 as it reaches the end of its defined "
            "retention period."
        ),
        default=True,
    )


check_automate_s3_data_retention._CHECK_ID = CHECK_ID
check_automate_s3_data_retention._CHECK_NAME = CHECK_NAME
