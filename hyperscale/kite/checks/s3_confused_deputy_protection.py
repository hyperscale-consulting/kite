import json

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.conditions import has_confused_deputy_protection
from hyperscale.kite.data import get_bucket_metadata
from hyperscale.kite.helpers import get_account_ids_in_scope


class S3ConfusedDeputyProtectionCheck:
    def __init__(self):
        self.check_id = "s3-confused-deputy-protection"
        self.check_name = "S3 Bucket Confused Deputy Protection"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check identifies S3 bucket policies that allow actions to be "
            "performed by service principals without proper confused deputy protection "
            "via conditions on aws:SourceAccount, aws:SourceArn, aws:SourceOrgID, or "
            "aws:SourceOrgPaths."
        )

    def _is_service_principal(self, principal) -> bool:
        """
        Check if a principal is a service principal.

        Args:
            principal: The principal to check (can be string or list)

        Returns:
            True if the principal is a service principal, False otherwise
        """
        if isinstance(principal, list):
            return any(self._is_service_principal(p) for p in principal)
        if not isinstance(principal, str):
            return False
        return principal.endswith(".amazonaws.com")

    def run(self) -> CheckResult:
        vulnerable_buckets = []

        # Get all bucket policies
        for account_id in get_account_ids_in_scope():
            buckets = get_bucket_metadata(account_id)

            for bucket in buckets:
                bucket_name = bucket["Name"]
                policy = bucket.get("Policy")

                if not policy:
                    continue

                try:
                    policy_doc = json.loads(policy)
                except json.JSONDecodeError:
                    continue

                for statement in policy_doc.get("Statement", []):
                    # Skip Deny statements as they are a security control
                    if statement.get("Effect") == "Deny":
                        continue

                    # Skip if statement has confused deputy protection
                    if has_confused_deputy_protection(statement.get("Condition", {})):
                        continue

                    # Check principals in the statement
                    principals = []
                    if "Principal" in statement:
                        if isinstance(statement["Principal"], dict):
                            principals.extend(statement["Principal"].values())
                        elif isinstance(statement["Principal"], str):
                            principals.append(statement["Principal"])

                    # Check if any principal is a service principal
                    if any(self._is_service_principal(p) for p in principals):
                        vulnerable_buckets.append(
                            {
                                "account_id": account_id,
                                "bucket_name": bucket_name,
                                "statement": statement,
                            }
                        )

        if not vulnerable_buckets:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="All S3 bucket policies have proper confused deputy protection.",
            )

        return CheckResult(
            status=CheckStatus.FAIL,
            reason=(
                f"Found {len(vulnerable_buckets)} S3 buckets with policies that could "
                "be vulnerable to confused deputy attacks."
            ),
        )
