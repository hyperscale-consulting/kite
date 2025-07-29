from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_ec2_instances
from hyperscale.kite.helpers import get_account_ids_in_scope


class UseOfHigherLevelServicesCheck:
    def __init__(self):
        self.check_id = "use-of-higher-level-services"
        self.check_name = "Use of Higher-Level Services"

    @property
    def question(self) -> str:
        return (
            "Are higher-level managed services favored over lower-level "
            "services such as EC2?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that higher-level AWS services are preferred over "
            "lower-level services like EC2."
        )

    def run(self) -> CheckResult:
        account_ids = get_account_ids_in_scope()
        config = Config.get()
        ec2_instances_by_account = {}

        for account_id in account_ids:
            account_instances = {}
            for region in config.active_regions:
                instances = get_ec2_instances(account_id, region)
                if instances:
                    account_instances[region] = instances

            if account_instances:
                ec2_instances_by_account[account_id] = account_instances

        if not ec2_instances_by_account:
            return CheckResult(
                status=CheckStatus.PASS,
                reason=(
                    "No EC2 instances found in in-scope accounts. "
                    "Higher-level services appear to be preferred."
                ),
            )

        context = (
            "EC2 instances were found in your in-scope accounts. "
            "Consider the following factors:\n"
            "- Are higher-level managed services favored over lower-level "
            "services such as EC2?\n"
            "- Are the total costs and risks associated with securing "
            "lower-level services accounted for when making decisions?\n\n"
            "EC2 Instances Found:\n"
        )

        for account_id, regions in ec2_instances_by_account.items():
            context += f"\nAccount: {account_id}\n"
            for region, instances in regions.items():
                context += f"  Region: {region}\n"
                for instance in instances:
                    context += (
                        f"    - Instance {instance.get('InstanceId')} - "
                        f"State: {instance.get('State', {}).get('Name')}\n"
                    )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
            details={"ec2_instances": ec2_instances_by_account},
        )
