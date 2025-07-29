from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_flow_logs
from hyperscale.kite.data import get_vpcs
from hyperscale.kite.helpers import get_account_ids_in_scope


class VpcFlowLogsEnabledCheck:
    def __init__(self):
        self.check_id = "vpc-flow-logs-enabled"
        self.check_name = "VPC Flow Logs Enabled"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that all VPCs have flow logs enabled and properly "
            "configured to capture traffic."
        )

    def run(self) -> CheckResult:
        config = Config.get()
        failing_vpcs: list[dict[str, str]] = []

        # Get all in-scope accounts
        accounts = get_account_ids_in_scope()

        # Check each account in each active region
        for account in accounts:
            for region in config.active_regions:
                # Get VPCs and flow logs for this account and region
                vpcs = get_vpcs(account, region)
                flow_logs = get_flow_logs(account, region)

                # Create a set of VPC IDs that have flow logs enabled
                vpcs_with_flow_logs = {
                    log["ResourceId"]
                    for log in flow_logs
                    if log.get("ResourceId") and log.get("FlowLogStatus") == "ACTIVE"
                }

                # Check each VPC
                for vpc in vpcs:
                    vpc_id = vpc.get("VpcId")
                    if not vpc_id:
                        continue

                    if vpc_id not in vpcs_with_flow_logs:
                        failing_vpcs.append(
                            {
                                "id": vpc_id,
                                "account": account,
                                "region": region,
                                "reason": "No active flow logs found",
                            }
                        )

        if not failing_vpcs:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="All VPCs have flow logs enabled",
            )

        return CheckResult(
            status=CheckStatus.FAIL,
            reason=f"Found {len(failing_vpcs)} VPC(s) without flow logs enabled",
            details={
                "failing_resources": failing_vpcs,
            },
        )
