from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization
from hyperscale.kite.helpers import get_organizational_trail


class OrganizationalCloudTrailCheck:
    def __init__(self):
        self.check_id = "organizational-cloudtrail"
        self.check_name = "Organizational CloudTrail"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that AWS Organizations is being used and that there "
            "is at least one Organizational CloudTrail trail."
        )

    def run(self) -> CheckResult:
        org = get_organization()
        if org is None:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "AWS Organizations is not being used, so organizational "
                    "CloudTrail cannot be assessed."
                ),
            )
        trail, account, region = get_organizational_trail()
        if trail is None:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="No organizational CloudTrail trail was found in any active "
                "region.",
            )
        validation_enabled = trail.get("LogFileValidationEnabled", False)
        if not validation_enabled:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "An organizational CloudTrail trail is configured, but log file "
                    "validation is not enabled."
                ),
                details={
                    "trail": {
                        "name": trail["Name"],
                        "account": account,
                        "region": region,
                        "s3_bucket": trail["S3BucketName"],
                        "log_group_arn": trail["CloudWatchLogsLogGroupArn"],
                        "validation_enabled": validation_enabled,
                    },
                },
            )
        return CheckResult(
            status=CheckStatus.PASS,
            reason="An organizational CloudTrail trail is configured.",
            details={
                "trail": {
                    "name": trail["Name"],
                    "account": account,
                    "region": region,
                    "s3_bucket": trail["S3BucketName"],
                    "log_group_arn": trail["CloudWatchLogsLogGroupArn"],
                    "validation_enabled": validation_enabled,
                },
            },
        )
