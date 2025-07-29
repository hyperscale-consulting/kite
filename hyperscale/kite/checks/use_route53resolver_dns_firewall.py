from typing import Any

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_ec2_instances
from hyperscale.kite.data import get_ecs_clusters
from hyperscale.kite.data import get_eks_clusters
from hyperscale.kite.data import get_elbv2_load_balancers
from hyperscale.kite.data import get_lambda_functions
from hyperscale.kite.data import get_rds_instances
from hyperscale.kite.data import get_route53resolver_firewall_domain_lists
from hyperscale.kite.data import get_route53resolver_firewall_rule_group_associations
from hyperscale.kite.data import get_route53resolver_firewall_rule_groups
from hyperscale.kite.data import get_vpcs
from hyperscale.kite.helpers import get_account_ids_in_scope


class UseRoute53ResolverDnsFirewallCheck:
    def __init__(self):
        self.check_id = "use-route53resolver-dns-firewall"
        self.check_name = "Use Route 53 Resolver DNS Firewall"

    @property
    def question(self) -> str:
        return (
            "Do you use Route 53 Resolver DNS firewall to control DNS egress from VPCs?"
        )

    @property
    def description(self) -> str:
        return (
            "This check helps you confirm whether Route 53 Resolver DNS firewall is "
            "used to control DNS egress from VPCs."
        )

    def run(self) -> CheckResult:
        analysis = _analyze_dns_firewall_usage()

        # If no VPCs with resources found, automatically pass
        if "No VPCs with resources found" in analysis:
            return CheckResult(
                status=CheckStatus.PASS,
                reason=(
                    "No VPCs with resources found. This check passes automatically "
                    "as there are no VPCs to evaluate."
                ),
            )

        # For VPCs with resources, require manual review
        message = (
            "Route 53 Resolver DNS firewall allows you to control which domains your "
            "resources can query, helping to prevent data exfiltration and malware "
            "communication through DNS.\n\n"
            "Below is a summary of VPCs with resources and their DNS firewall "
            "configurations:\n"
        )
        message += f"{analysis}"

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )


def _get_vpcs_with_resources() -> dict[str, list[str]]:
    """Get VPCs that have resources in them, organized by account."""
    vpcs_with_resources = {}
    accounts = get_account_ids_in_scope()
    regions = Config.get().active_regions

    for account_id in accounts:
        vpcs_with_resources[account_id] = []

        for region in regions:
            # Get VPCs
            vpcs = get_vpcs(account_id, region)

            for vpc in vpcs:
                vpc_id = vpc.get("VpcId")
                if not vpc_id:
                    continue

                # Check if VPC has resources
                has_resources = False

                # Check EC2 instances
                ec2_instances = get_ec2_instances(account_id, region)
                for instance in ec2_instances:
                    if instance.get("VpcId") == vpc_id:
                        has_resources = True
                        break

                # Check Lambda functions (if they have VPC config)
                if not has_resources:
                    lambda_functions = get_lambda_functions(account_id, region)
                    for func in lambda_functions:
                        vpc_config = func.get("VpcConfig", {})
                        if vpc_config.get("VpcId") == vpc_id:
                            has_resources = True
                            break

                # Check RDS instances
                if not has_resources:
                    rds_instances = get_rds_instances(account_id, region)
                    for rds in rds_instances:
                        if rds.get("DBSubnetGroup", {}).get("VpcId") == vpc_id:
                            has_resources = True
                            break

                # Check ELBv2 load balancers
                if not has_resources:
                    load_balancers = get_elbv2_load_balancers(account_id, region)
                    for lb in load_balancers:
                        if lb.get("VpcId") == vpc_id:
                            has_resources = True
                            break

                # Check EKS clusters
                if not has_resources:
                    eks_clusters = get_eks_clusters(account_id, region)
                    for cluster in eks_clusters:
                        if cluster.get("ResourcesVpcConfig", {}).get("VpcId") == vpc_id:
                            has_resources = True
                            break

                # Check ECS clusters (if they have VPC config)
                if not has_resources:
                    ecs_clusters = get_ecs_clusters(account_id, region)
                    for _ in ecs_clusters:
                        # ECS clusters don't directly have VPC ID, but services might
                        # For now, we'll assume ECS clusters have resources
                        has_resources = True
                        break

                if has_resources and vpc_id not in vpcs_with_resources[account_id]:
                    vpcs_with_resources[account_id].append(vpc_id)

    return vpcs_with_resources


def _get_dns_firewall_details() -> dict[str, dict[str, Any]]:
    """Get DNS firewall details organized by VPC ID."""
    dns_firewalls = {}
    accounts = get_account_ids_in_scope()
    regions = Config.get().active_regions

    # Get all firewall rule groups and domain lists for reference
    all_rule_groups = {}
    all_domain_lists = {}

    for account_id in accounts:
        for region in regions:
            rule_groups = get_route53resolver_firewall_rule_groups(account_id, region)
            for group in rule_groups:
                all_rule_groups[group.get("Id")] = group

            domain_lists = get_route53resolver_firewall_domain_lists(account_id, region)
            for domain_list in domain_lists:
                all_domain_lists[domain_list.get("Id")] = domain_list

    # Get firewall associations
    for account_id in accounts:
        for region in regions:
            associations = get_route53resolver_firewall_rule_group_associations(
                account_id, region
            )

            for association in associations:
                vpc_id = association.get("VpcId")
                if not vpc_id:
                    continue

                rule_group_id = association.get("FirewallRuleGroupId")
                rule_group = all_rule_groups.get(rule_group_id, {})

                firewall_info = {
                    "association": association,
                    "rule_group": rule_group,
                    "rules": [],
                }

                # Get rules for this rule group
                for rule in rule_group.get("FirewallRules", []):
                    domain_list_id = rule.get("FirewallDomainListId")
                    domain_list = all_domain_lists.get(domain_list_id, {})

                    rule_info = {"rule": rule, "domain_list": domain_list}
                    firewall_info["rules"].append(rule_info)

                dns_firewalls[vpc_id] = firewall_info

    return dns_firewalls


def _analyze_dns_firewall_usage() -> str:
    """Analyze DNS firewall usage across VPCs with resources."""
    analysis = ""
    vpcs_with_resources = _get_vpcs_with_resources()
    dns_firewalls = _get_dns_firewall_details()

    total_vpcs = 0
    vpcs_with_firewall = 0

    for account_id, vpc_ids in vpcs_with_resources.items():
        if not vpc_ids:
            continue

        account_analysis = f"\nAccount: {account_id}\n"
        account_analysis += f"  VPCs with resources: {len(vpc_ids)}\n"

        for vpc_id in vpc_ids:
            total_vpcs += 1
            account_analysis += f"    VPC: {vpc_id}\n"

            if vpc_id in dns_firewalls:
                vpcs_with_firewall += 1
                firewall_info = dns_firewalls[vpc_id]
                association = firewall_info["association"]
                rule_group = firewall_info["rule_group"]

                account_analysis += (
                    f"      DNS Firewall: {association.get('Name', 'Unnamed')}\n"
                )
                account_analysis += (
                    f"      Rule Group: {rule_group.get('Name', 'Unnamed')}\n"
                )
                account_analysis += (
                    f"      Status: {association.get('Status', 'Unknown')}\n"
                )
                account_analysis += (
                    f"      Priority: {association.get('Priority', 'Unknown')}\n"
                )
                account_analysis += (
                    f"      Mutation Protection: "
                    f"{association.get('MutationProtection', 'Unknown')}\n"
                )

                # Show rules
                rules = firewall_info["rules"]
                if rules:
                    account_analysis += "      Rules:\n"
                    for rule_info in rules:
                        rule = rule_info["rule"]
                        domain_list = rule_info["domain_list"]

                        account_analysis += f"        - {rule.get('Name', 'Unnamed')}\n"
                        account_analysis += (
                            f"          Action: {rule.get('Action', 'Unknown')}\n"
                        )
                        account_analysis += (
                            f"          Priority: {rule.get('Priority', 'Unknown')}\n"
                        )
                        account_analysis += (
                            f"          Domain List: "
                            f"{domain_list.get('Name', 'Unnamed')}\n"
                        )

                        # Show domains if available
                        domains = domain_list.get("Domains", [])
                        if domains:
                            account_analysis += (
                                f"          Domains: {', '.join(domains[:5])}"
                            )
                            if len(domains) > 5:
                                account_analysis += f" (and {len(domains) - 5} more)"
                            account_analysis += "\n"

                        # Show block response for BLOCK actions
                        if rule.get("Action") == "BLOCK":
                            block_response = rule.get("BlockResponse", "Unknown")
                            account_analysis += (
                                f"          Block Response: {block_response}\n"
                            )

                        account_analysis += "\n"
                else:
                    account_analysis += "      No rules configured\n\n"
            else:
                account_analysis += "      ⚠️  NO DNS FIREWALL CONFIGURED\n\n"

        analysis += account_analysis

    if total_vpcs == 0:
        analysis = "\nNo VPCs with resources found in any account or region.\n"
    else:
        analysis += "\nSummary:\n"
        analysis += f"  Total VPCs with resources: {total_vpcs}\n"
        analysis += f"  VPCs with DNS firewall: {vpcs_with_firewall}\n"
        analysis += f"  VPCs without DNS firewall: {total_vpcs - vpcs_with_firewall}\n"

    return analysis
