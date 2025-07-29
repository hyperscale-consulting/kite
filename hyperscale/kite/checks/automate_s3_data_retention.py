from collections import defaultdict

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_bucket_metadata
from hyperscale.kite.helpers import get_account_ids_in_scope


class AutomateS3DataRetentionCheck:
    def __init__(self):
        self.check_id = "automate-s3-data-retention"
        self.check_name = "Automate S3 Data Retention"

    @property
    def question(self) -> str:
        return (
            "Are S3 lifecycle policies used consistently to automatically delete "
            "data stored in S3 as it reaches the end of its defined retention period?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that S3 lifecycle policies are used consistently "
            "to automatically delete data stored in S3 as it reaches the end of "
            "its defined retention period."
        )

    def _format_buckets_by_retention(self, buckets):
        retention_groups = defaultdict(list)
        for bucket in buckets:
            name = bucket.get("Name")
            if not name:
                continue
            retention = None
            lifecycle_rules = bucket.get("LifecycleRules")
            if lifecycle_rules is not None:
                for rule in lifecycle_rules:
                    if "Expiration" in rule and "Days" in rule["Expiration"]:
                        days = rule["Expiration"]["Days"]
                        if retention is None or days < retention:
                            retention = days
            retention = retention if retention is not None else "Never Expire"
            retention_groups[str(retention)].append(name)
        output = []
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

    def run(self) -> CheckResult:
        buckets_by_retention = []
        accounts = get_account_ids_in_scope()
        for account in accounts:
            buckets = get_bucket_metadata(account)
            if buckets:
                buckets_by_retention.append(
                    f"\nAccount: {account} "
                    + self._format_buckets_by_retention(buckets)
                )
        message = (
            "Current S3 Buckets:\n"
            + "\n".join(buckets_by_retention)
            + "\n\nPlease review the retention periods above and consider:\n"
            "- Are S3 lifecycle policies used consistently across all buckets?\n"
            "- Are retention periods appropriate for the data stored in each bucket?\n"
            "- Is data automatically deleted when it reaches the end of its retention "
            "period?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
