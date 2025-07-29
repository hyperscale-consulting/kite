from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_bucket_metadata
from hyperscale.kite.helpers import get_account_ids_in_scope


class ImplementVersioningAndObjectLockingCheck:
    def __init__(self):
        self.check_id = "implement-versioning-and-object-locking"
        self.check_name = "Implement Versioning and Object Locking"

    @property
    def question(self) -> str:
        return (
            "Is versioning and object locking implemented on all S3 buckets where "
            "appropriate?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that versioning and object locking are implemented "
            "on all S3 buckets where appropriate."
        )

    def _get_buckets_without_protection(self) -> dict[str, list[dict]]:
        buckets_without_protection = {}
        for account_id in get_account_ids_in_scope():
            buckets = get_bucket_metadata(account_id)
            unprotected_buckets = []
            for bucket in buckets:
                versioning = bucket.get("Versioning")
                is_versioned = versioning and versioning == "Enabled"
                object_lock = bucket.get("ObjectLockConfiguration")
                is_locked = (
                    object_lock and object_lock.get("ObjectLockEnabled") == "Enabled"
                )
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

    def run(self) -> CheckResult:
        buckets_without_protection = self._get_buckets_without_protection()
        message = "S3 Buckets Without Versioning and Object Locking:\n\n"
        if not buckets_without_protection:
            message += (
                "All S3 buckets have both versioning and object locking enabled.\n"
            )
            return CheckResult(
                status=CheckStatus.PASS,
                reason=message,
                details={
                    "buckets_without_protection": buckets_without_protection,
                },
            )
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
            "Please review the above and confirm that versioning and object locking "
            "are implemented where appropriate\n"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
            details={
                "buckets_without_protection": buckets_without_protection,
            },
        )
