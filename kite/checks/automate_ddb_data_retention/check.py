"""Check for automated DynamoDB data retention."""

from typing import Any

from kite.config import Config
from kite.data import get_dynamodb_tables
from kite.helpers import get_account_ids_in_scope

CHECK_ID = "automate-ddb-data-retention"
CHECK_NAME = "Automate DynamoDB Data Retention"


def check_automate_ddb_data_retention() -> dict[str, Any]:
    """
    Check if DynamoDB TTL is enabled on all tables to automatically delete
    data when it reaches the end of its retention period.

    This check:
    1. Lists all DynamoDB tables across all accounts and regions
    2. Verifies that TTL is enabled on all tables
    3. Fails if any table does not have TTL enabled
    4. Passes if all tables have TTL enabled or if there are no tables

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    config = Config.get()
    tables_without_ttl = []

    # Get all in-scope accounts
    accounts = get_account_ids_in_scope()

    # Check each account in each active region
    for account in accounts:
        for region in config.active_regions:
            # Get tables for this account and region
            tables = get_dynamodb_tables(account, region)

            if tables:
                for table in tables:
                    table_name = table.get("TableName")
                    if not table_name:
                        continue

                    # Check if TTL is enabled
                    ttl_status = table.get("TimeToLiveDescription", {}).get(
                        "TimeToLiveStatus"
                    )
                    if ttl_status != "ENABLED":
                        tables_without_ttl.append(f"{account}/{region}/{table_name}")

    # Build the message
    if not tables_without_ttl:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "All DynamoDB tables have TTL enabled for automated data retention."
                )
            },
        }

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": (
                "The following DynamoDB tables do not have TTL enabled for "
                "automated data retention:\n"
                + "\n".join(f"- {table}" for table in sorted(tables_without_ttl))
                + "\n\nEnable TTL on these tables to automatically delete data "
                "when it reaches the end of its retention period."
            )
        },
    }


check_automate_ddb_data_retention._CHECK_ID = CHECK_ID
check_automate_ddb_data_retention._CHECK_NAME = CHECK_NAME
