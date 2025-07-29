from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class MaintainInventoryOfSharedResourcesCheck:
    def __init__(self):
        self.check_id = "maintain-inventory-of-shared-resources"
        self.check_name = "Maintain Inventory of Shared Resources"

    @property
    def question(self) -> str:
        return "Is an inventory of shared resources maintained?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that an inventory of shared resources is maintained."
        )

    def run(self) -> CheckResult:
        message = (
            "An inventory of shared resources should cover:\n"
            "1. S3 buckets\n"
            "2. SNS topics\n"
            "3. SQS queues\n"
            "4. Lambda functions\n"
            "5. KMS keys\n"
            "6. Other resources that are shared across accounts or with external "
            "parties\n\n"
            "The inventory should include the following informaiton:\n"
            "- What is shared\n"
            "- Who it is shared with\n"
            "- Why it is shared\n"
            "- When it was last reviewed\n"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
