from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class ApprovalProcessForResourceSharingCheck:
    def __init__(self):
        self.check_id = "approval-process-for-resource-sharing"
        self.check_name = "Approval Process for Resource Sharing"

    @property
    def question(self) -> str:
        return "Is there an approval process for resource sharing?"

    @property
    def description(self) -> str:
        return (
            "This check asks the user to confirm if there is an approval process for "
            "sharing resources across accounts or with external parties."
        )

    def run(self) -> CheckResult:
        message = (
            "Please confirm if there is an approval process for resource sharing.\n\n"
            "The approval process should include:\n"
            "1. Who can approve resource sharing requests\n"
            "2. What information is required for approval\n"
            "3. How long approvals are valid for\n"
            "4. How approvals are documented\n"
            "5. How approvals are reviewed and revoked\n\n"
            "This applies to sharing of:\n"
            "- S3 buckets\n"
            "- SNS topics\n"
            "- SQS queues\n"
            "- Lambda functions\n"
            "- KMS keys\n"
            "- Other resources that can be shared"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
