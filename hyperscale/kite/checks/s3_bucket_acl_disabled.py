from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import get_prowler_output


class S3BucketAclDisabledCheck:
    def __init__(self):
        self.check_id = "s3-bucket-acl-disabled"
        self.check_name = "S3 Bucket ACL Disabled"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return "This check verifies that S3 bucket ACLs are disabled."

    def run(self) -> CheckResult:
        prowler_results = get_prowler_output()
        check_id = "s3_bucket_acl_prohibited"
        failing_resources = []

        if check_id in prowler_results:
            results = prowler_results[check_id]
            for result in results:
                if result.status != "PASS":
                    failing_resources.append(
                        {
                            "account_id": result.account_id,
                            "resource_uid": result.resource_uid,
                            "resource_name": result.resource_name,
                            "resource_details": result.resource_details,
                            "region": result.region,
                            "status": result.status,
                        }
                    )

        passed = len(failing_resources) == 0
        message = (
            "All S3 buckets have ACLs disabled."
            if passed
            else f"Found {len(failing_resources)} S3 buckets with ACLs enabled."
        )

        return CheckResult(
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            reason=message,
            details={
                "message": message,
                "failing_resources": failing_resources,
            },
        )
