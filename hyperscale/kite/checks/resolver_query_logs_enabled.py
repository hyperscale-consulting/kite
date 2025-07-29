from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_route53resolver_query_log_config_associations
from hyperscale.kite.data import get_vpcs
from hyperscale.kite.helpers import get_account_ids_in_scope


class ResolverQueryLogsEnabledCheck:
    def __init__(self):
        self.check_id = "resolver-query-logs-enabled"
        self.check_name = "Route 53 Resolver Query Logs Enabled"

    @property
    def question(self) -> str:
        return "Do all VPCs have Route 53 Resolver query logs enabled?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that each VPC in each account and region has at least "
            "one resolver query log config association and that the associations are "
            "properly configured."
        )

    def run(self) -> CheckResult:
        config = Config.get()
        failing_vpcs: list[dict[str, str]] = []

        accounts = get_account_ids_in_scope()
        for account in accounts:
            for region in config.active_regions:
                vpcs = get_vpcs(account, region)
                query_log_associations = (
                    get_route53resolver_query_log_config_associations(account, region)
                )

                vpcs_with_query_logs = {
                    assoc["ResourceId"]
                    for assoc in query_log_associations
                    if assoc.get("ResourceId") and assoc.get("Status") == "ACTIVE"
                }

                for vpc in vpcs:
                    vpc_id = vpc.get("VpcId")
                    if not vpc_id:
                        continue
                    if vpc_id not in vpcs_with_query_logs:
                        failing_vpcs.append(
                            {
                                "id": vpc_id,
                                "account": account,
                                "region": region,
                            }
                        )

        if not failing_vpcs:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="All VPCs have Route 53 Resolver query logs enabled.",
            )

        return CheckResult(
            status=CheckStatus.FAIL,
            reason=(
                f"Found {len(failing_vpcs)} VPC(s) without Route 53 Resolver query "
                "logs enabled."
            ),
            details={
                "vpcs_without_query_logs": failing_vpcs,
            },
        )
