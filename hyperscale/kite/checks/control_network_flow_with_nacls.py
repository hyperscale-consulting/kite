from collections import defaultdict

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.utils import get_name_from_tag
from hyperscale.kite.checks.utils import get_vpcs_with_resources
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_nacls
from hyperscale.kite.helpers import get_account_ids_in_scope
from hyperscale.kite.prowler import get_prowler_output


def _analyze() -> str:
    accounts = get_account_ids_in_scope()
    config = Config.get()
    analysis = "NACL Network Flow Analysis:\n\n"
    vpcs_by_account_and_region = defaultdict(dict)
    for account_id in accounts:
        for region in config.active_regions:
            vpcs_with_resources = get_vpcs_with_resources(account_id, region)
            if vpcs_with_resources:
                vpcs_by_account_and_region[account_id][region] = vpcs_with_resources

    prowler_output = get_prowler_output()
    for account_id, regions in vpcs_by_account_and_region.items():
        analysis += account_id + "\n" + "=" * 50 + "\n\n"
        for region, vpcs in regions.items():
            nacls = get_nacls(account_id, region)
            analysis += f"Region: {region}\n" + "-" * 30 + "\n\n"
            for vpc in vpcs:
                analysis += f"VPC: {vpc['VpcId']} - CIDR: {vpc['CidrBlock']}\n"
                for subnet in vpc["Subnets"]:
                    analysis += _analyze_subnet(subnet, nacls, prowler_output)

    return analysis


def _summarize_nacl_rules(nacl):
    summary = {"ingress": [], "egress": []}
    protocol_map = {
        "-1": "ALL",
        "1": "ICMP",
        "6": "TCP",
        "17": "UDP",
    }
    entries = sorted(nacl.get("Entries", []), key=lambda e: e.get("RuleNumber", 32767))
    for entry in entries:
        action = entry.get("RuleAction", "allow")
        egress = entry.get("Egress", False)
        direction = "egress" if egress else "ingress"
        protocol = str(entry.get("Protocol", "-1"))
        proto_str = protocol_map.get(protocol, protocol)
        cidr = entry.get("CidrBlock", "?")
        port_range = entry.get("PortRange")
        if port_range:
            port_str = f"ports {port_range.get('From')}–{port_range.get('To')}"
        else:
            port_str = "all ports"
        direction_word = "to" if direction == "egress" else "from"
        summary[direction].append(
            f"Rule {entry.get('RuleNumber')}: {action.upper()} {proto_str} "
            f"{port_str} {direction_word} {cidr}"
        )
    return summary


def _analyze_subnet(subnet, nacls, prowler_output):
    subnet_id = subnet["SubnetId"]
    subnet_name = get_name_from_tag(subnet)
    subnet_cidr = subnet["CidrBlock"]
    az = subnet["AvailabilityZone"]
    analysis = (
        f"  Subnet: {subnet_id} (Name: {subnet_name}) - CIDR: {subnet_cidr} - AZ: {az}"
    )
    analysis += "\n"
    resources_by_type = subnet.get("Resources", {})
    for resource_type, resources in resources_by_type.items():
        analysis += f"    {resource_type}:"
        analysis += "\n"
        for resource in resources:
            resource_name = resource["Name"]
            analysis += f"      {resource_name}:\n"
            analysis += _analyze_nacls(subnet_id, nacls, prowler_output)

    return analysis


def _analyze_nacls(subnet_id, nacls, prowler_output):
    analysis = ""
    prowler_checks = [
        "ec2_networkacl_allow_ingress_tcp_port_22",
        "ec2_networkacl_allow_ingress_tcp_port_3389",
        "ec2_networkacl_allow_ingress_any_port",
    ]
    nacl = _get_nacl_for_subnet(subnet_id, nacls)
    if nacl:
        nacl_summary = _summarize_nacl_rules(nacl)
        nacl_id = nacl.get("NetworkAclId")
        analysis += f"    NACL ({nacl_id}) Rules (Ingress):\n"
        for rule in nacl_summary["ingress"]:
            analysis += f"      {rule}\n"
        analysis += f"    NACL ({nacl_id}) Rules (Egress):\n"
        for rule in nacl_summary["egress"]:
            analysis += f"      {rule}\n"
        warnings = []
        for check_id in prowler_checks:
            for prowler_result in prowler_output.get(check_id, []):
                if (
                    prowler_result.resource_name == nacl_id
                    and prowler_result.status != "PASS"
                ):
                    warnings.append(
                        f"⚠️ {check_id} failed: "
                        f"{prowler_result.extended_status or prowler_result.status}"
                    )
        if warnings:
            for warning in warnings:
                analysis += f"      {warning}\n"
    else:
        analysis += "    No NACL associated with this subnet.\n"
    return analysis


def _get_nacl_for_subnet(subnet_id, nacls):
    for nacl in nacls:
        for assoc in nacl.get("Associations", []):
            if assoc.get("SubnetId") == subnet_id:
                return nacl
    return None


class ControlNetworkFlowWithNaclsCheck:
    def __init__(self):
        self.check_id = "control-network-flows-with-nacls"
        self.check_name = "Control Network Flows with NACLs"

    @property
    def question(self) -> str:
        return (
            "Are NACLs used to restrict ingress and egress traffic to only the flows "
            "necessary for each workload at each network layer?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that Network Access Control Lists (NACLs) are used "
            "to restrict ingress and egress traffic to only the flows necessary for "
            "each workload at each network layer."
        )

    def run(self) -> CheckResult:
        nacl_analysis = _analyze()
        message = (
            "Below is a summary of each VPC and subnet with resources, including a "
            "summary of the NACL rules applied to each subnet.\n\n"
            f"{nacl_analysis}"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
