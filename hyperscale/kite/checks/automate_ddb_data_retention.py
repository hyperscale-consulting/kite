from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_dynamodb_tables
from hyperscale.kite.helpers import get_account_ids_in_scope


class AutomateDdbDataRetentionCheck:
    def __init__(self):
        self.check_id = "automate-ddb-data-retention"
        self.check_name = "Automate DynamoDB Data Retention"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that DynamoDB TTL is enabled on all tables to "
            "automatically delete data when it reaches the end of its retention period."
        )

    def run(self) -> CheckResult:
        config = Config.get()
        tables_without_ttl = []
        accounts = get_account_ids_in_scope()
        for account in accounts:
            for region in config.active_regions:
                tables = get_dynamodb_tables(account, region)
                if tables:
                    for table in tables:
                        table_name = table.get("TableName")
                        if not table_name:
                            continue
                        ttl_status = table.get("TimeToLiveDescription", {}).get(
                            "TimeToLiveStatus"
                        )
                        if ttl_status != "ENABLED":
                            tables_without_ttl.append(
                                f"{account}/{region}/{table_name}"
                            )
        if not tables_without_ttl:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="All DynamoDB tables have TTL enabled for automated data "
                "retention.",
            )
        return CheckResult(
            status=CheckStatus.FAIL,
            reason=(
                "The following DynamoDB tables do not have TTL enabled for "
                "automated data retention:\n"
                + "\n".join(f"- {table}" for table in sorted(tables_without_ttl))
                + "\n\nEnable TTL on these tables to automatically delete data "
                "when it reaches the end of its retention period."
            ),
        )
