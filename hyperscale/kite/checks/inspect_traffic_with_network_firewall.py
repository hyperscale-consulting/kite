from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.utils import get_name_from_tag
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_networkfirewall_firewalls
from hyperscale.kite.data import get_vpcs
from hyperscale.kite.helpers import get_account_ids_in_scope


class InspectTrafficWithNetworkFirewallCheck:
    def __init__(self):
        self.check_id = "inspect-traffic-with-network-firewall"
        self.check_name = "Inspect Traffic with Network Firewall"

    @property
    def question(self) -> str:
        return "Do you use Network Firewall to inspect traffic in your VPCs?"

    @property
    def description(self) -> str:
        return (
            "This check verifies whether Network Firewall is properly configured "
            "to inspect traffic in your VPCs."
        )

    def _pre_check(self) -> tuple[bool, dict]:
        accounts = get_account_ids_in_scope()
        regions = Config.get().active_regions
        total_firewalls = 0
        for account_id in accounts:
            for region in regions:
                firewalls = get_networkfirewall_firewalls(account_id, region)
                total_firewalls += len(firewalls)
        if total_firewalls == 0:
            msg = "No Network Firewalls found across all accounts and regions."
            result = {
                "check_id": self.check_id,
                "check_name": self.check_name,
                "status": "FAIL",
                "details": {"message": msg},
            }
            return False, result
        return True, {}

    def _analyze_network_firewalls(self) -> str:
        accounts = get_account_ids_in_scope()
        regions = Config.get().active_regions
        analysis_lines = []
        analysis_lines.append("Network Firewall Configuration Analysis")
        analysis_lines.append("=" * 50)
        analysis_lines.append("")
        vpcs_with_firewalls = set()
        total_firewalls = 0
        for account_id in accounts:
            account_has_firewalls = False
            account_has_resources = False
            for region in regions:
                firewalls = get_networkfirewall_firewalls(account_id, region)
                vpcs = get_vpcs(account_id, region)
                if firewalls:
                    account_has_firewalls = True
                    total_firewalls += len(firewalls)
                    analysis_lines.append(f"Account {account_id} - Region {region}:")
                    analysis_lines.append("-" * 60)
                    for firewall in firewalls:
                        analysis_lines.append(
                            f"  Firewall: {firewall.get('FirewallName', 'N/A')}"
                        )
                        analysis_lines.append(
                            f"  VPC ID: {firewall.get('VpcId', 'N/A')}"
                        )
                        analysis_lines.append(
                            f"  Description: {firewall.get('Description', 'N/A')}"
                        )
                        status = firewall.get("FirewallStatus", {})
                        analysis_lines.append(
                            f"  Status: {status.get('Status', 'N/A')}"
                        )
                        analysis_lines.append("")
                        vpc_id = firewall.get("VpcId")
                        if vpc_id:
                            vpc_key = f"{account_id}:{region}:{vpc_id}"
                            vpcs_with_firewalls.add(vpc_key)
                if vpcs:
                    account_has_resources = True
            if account_has_firewalls or account_has_resources:
                if not account_has_firewalls:
                    analysis_lines.append(
                        f"Account {account_id}: No Network Firewalls configured"
                    )
                    analysis_lines.append("")
        analysis_lines.append("VPCs Without Network Firewalls:")
        analysis_lines.append("=" * 40)
        analysis_lines.append("")
        vpcs_without_firewalls = []
        for account_id in accounts:
            for region in regions:
                vpcs = get_vpcs(account_id, region)
                for vpc in vpcs:
                    vpc_id = vpc.get("VpcId")
                    if vpc_id:
                        vpc_key = f"{account_id}:{region}:{vpc_id}"
                        if vpc_key not in vpcs_with_firewalls:
                            vpcs_without_firewalls.append(
                                {
                                    "account_id": account_id,
                                    "region": region,
                                    "vpc_id": vpc_id,
                                    "vpc_name": get_name_from_tag(vpc),
                                }
                            )
        if vpcs_without_firewalls:
            for vpc_info in vpcs_without_firewalls:
                vpc_id = vpc_info["vpc_id"]
                vpc_name = vpc_info["vpc_name"]
                account_id = vpc_info["account_id"]
                region = vpc_info["region"]
                warning_msg = (
                    f"  WARNING: VPC {vpc_id} ({vpc_name}) in account "
                    f"{account_id} region {region} has no Network Firewall"
                )
                analysis_lines.append(warning_msg)
        else:
            analysis_lines.append("  All VPCs have Network Firewalls configured")
        analysis_lines.append("")
        analysis_lines.append(f"Summary: {total_firewalls} Network Firewalls found")
        analysis_lines.append(f"VPCs without firewalls: {len(vpcs_without_firewalls)}")
        return "\n".join(analysis_lines)

    def run(self) -> CheckResult:
        pre_check_passed, pre_check_result = self._pre_check()
        if not pre_check_passed:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=pre_check_result["details"]["message"],
            )
        analysis = self._analyze_network_firewalls()
        message = (
            "AWS Network Firewall provides stateful inspection, intrusion prevention, "
            "and web filtering capabilities for your VPC traffic.\n\n"
            "Below is a summary of Network Firewall configurations and VPCs without "
            "firewalls:\n"
        )
        message += f"{analysis}"
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
