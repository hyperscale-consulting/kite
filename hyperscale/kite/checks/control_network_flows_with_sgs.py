from collections import defaultdict

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.utils import get_name_from_tag
from hyperscale.kite.checks.utils import get_vpcs_with_resources
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_security_groups
from hyperscale.kite.helpers import get_account_ids_in_scope
from hyperscale.kite.prowler import get_prowler_output

prowler_checks = [
    "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
    "ec2_securitygroup_allow_ingress_from_internet_to_port_mongodb_27017_27018",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_ftp_port_20_21",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23",
    "ec2_securitygroup_with_many_ingress_egress_rules",
]


def _summarize_security_group_rules(sg):
    summary = {"ingress": [], "egress": []}
    for rule in sg.get("IpPermissions", []):
        protocol = str(rule.get("IpProtocol", "-1"))
        proto_str = "ALL" if protocol == "-1" else protocol
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        if from_port and to_port:
            port_str = f"ports {from_port}–{to_port}"
        elif from_port:
            port_str = f"port {from_port}"
        else:
            port_str = "all ports"
        ip_ranges = rule.get("IpRanges", [])
        for ip_range in ip_ranges:
            cidr = ip_range.get("CidrIp", "?")
            summary["ingress"].append(f"ALLOW {proto_str} {port_str} from {cidr}")
        user_id_group_pairs = rule.get("UserIdGroupPairs", [])
        for group_pair in user_id_group_pairs:
            group_id = group_pair.get("GroupId", "?")
            summary["ingress"].append(
                f"ALLOW {proto_str} {port_str} from SG {group_id}"
            )
    for rule in sg.get("IpPermissionsEgress", []):
        protocol = str(rule.get("IpProtocol", "-1"))
        proto_str = "ALL" if protocol == "-1" else protocol
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        if from_port and to_port:
            port_str = f"ports {from_port}–{to_port}"
        elif from_port:
            port_str = f"port {from_port}"
        else:
            port_str = "all ports"
        ip_ranges = rule.get("IpRanges", [])
        for ip_range in ip_ranges:
            cidr = ip_range.get("CidrIp", "?")
            summary["egress"].append(f"ALLOW {proto_str} {port_str} to {cidr}")
        user_id_group_pairs = rule.get("UserIdGroupPairs", [])
        for group_pair in user_id_group_pairs:
            group_id = group_pair.get("GroupId", "?")
            summary["egress"].append(f"ALLOW {proto_str} {port_str} to SG {group_id}")
    return summary


def _get_security_group_details(sg_id, sg_details):
    for sg in sg_details:
        if sg["GroupId"] == sg_id:
            return sg
    return None


def _analyze_security_groups(resource, sg_details, prowler_output):
    analysis = ""
    sg_ids = resource.get("SecurityGroupIds", [])
    if not sg_ids:
        analysis += "        No security groups found\n"
        return analysis
    for sg_id in sg_ids:
        detail = _get_security_group_details(sg_id, sg_details)
        if detail:
            sg_name = detail["GroupName"]
            analysis += f"        SG {sg_id}"
            if sg_name:
                analysis += f" ({sg_name})"
            analysis += ":\n"
            sg_summary = _summarize_security_group_rules(detail)
            if sg_summary["ingress"]:
                analysis += "          Ingress:\n"
                for rule in sg_summary["ingress"]:
                    analysis += f"            {rule}\n"
            if sg_summary["egress"]:
                analysis += "          Egress:\n"
                for rule in sg_summary["egress"]:
                    analysis += f"            {rule}\n"
            warnings = []
            for check_id in prowler_checks:
                for prowler_result in prowler_output.get(check_id, []):
                    if (
                        prowler_result.resource_name == sg_id
                        and prowler_result.status != "PASS"
                    ):
                        warnings.append(
                            f"⚠️ {check_id} failed: "
                            f"{prowler_result.extended_status or prowler_result.status}"
                        )
            if warnings:
                for warning in warnings:
                    analysis += f"          {warning}\n"
        else:
            analysis += f"        SG {sg_id} (not found)\n"
    return analysis


def _analyze_subnet(subnet, sg_details, prowler_output):
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
            analysis += _analyze_security_groups(resource, sg_details, prowler_output)

    return analysis


def _analyze() -> str:
    accounts = get_account_ids_in_scope()
    config = Config.get()
    analysis = "Security Group Network Flow Analysis:\n\n"
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
            sg_details = get_security_groups(account_id, region)
            analysis += f"Region: {region}\n" + "-" * 30 + "\n\n"
            for vpc in vpcs:
                analysis += f"VPC: {vpc['VpcId']} - CIDR: {vpc['CidrBlock']}\n"
                for subnet in vpc["Subnets"]:
                    analysis += _analyze_subnet(subnet, sg_details, prowler_output)

    return analysis


class ControlNetworkFlowsWithSGsCheck:
    def __init__(self):
        self.check_id = "control-network-flows-with-sgs"
        self.check_name = "Control Network Flows with Security Groups"

    @property
    def question(self) -> str:
        return (
            "Are Security Groups used to restrict ingress and egress traffic to only "
            "the flows necessary for each workload at each network layer?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that Security Groups are used to restrict "
            "ingress and egress traffic to only the flows necessary for each workload "
            "at each network layer."
        )

    def run(self) -> CheckResult:
        sg_analysis = _analyze()
        message = (
            "Below is a summary of each VPC and subnet with resources, including a "
            "summary of the security group rules applied to each resource.\n\n"
            f"{sg_analysis}"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
