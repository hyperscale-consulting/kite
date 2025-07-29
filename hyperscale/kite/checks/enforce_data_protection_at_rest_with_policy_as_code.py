from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class EnforceDataProtectionAtRestWithPolicyAsCodeCheck:
    def __init__(self):
        self.check_id = "enforce-data-protection-at-rest-with-policy-as-code"
        self.check_name = "Enforce Data Protection at Rest with Policy as Code"

    @property
    def question(self) -> str:
        return (
            "Are policy-as-code evaluation tools used to detect and prevent "
            "misconfigurations relating to protecting data at rest in CI/CD pipelines?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that policy-as-code evaluation tools (such as "
            "CloudFormation Guard) are used in CI/CD pipelines to detect and prevent "
            "misconfigurations related to protecting data at rest."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following:\n"
            "- Are tools like CloudFormation Guard used to evaluate infrastructure as "
            "code?\n"
            "- Do the policies check for encryption requirements on:\n"
            "  - S3 buckets\n"
            "  - RDS instances\n"
            "  - EBS volumes\n"
            "  - EFS file systems\n"
            "  - DynamoDB tables\n"
            "  - SQS queues\n"
            "  - SNS topics\n"
            "  - CloudWatch Log Groups\n"
            "  - Other data storage services\n"
            "- Are the policies enforced in CI/CD pipelines before deployment?\n"
            "- Are violations blocked from being deployed?\n"
            "- Are developers notified of policy violations?\n"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
