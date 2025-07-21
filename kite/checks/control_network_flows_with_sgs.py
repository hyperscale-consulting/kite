from collections import defaultdict

from kite.checks.core import CheckResult
from kite.checks.core import CheckStatus
from kite.checks.utils import get_name_from_tag
from kite.config import Config
from kite.data import get_ec2_instances
from kite.data import get_ecs_clusters
from kite.data import get_efs_file_systems
from kite.data import get_eks_clusters
from kite.data import get_elbv2_load_balancers
from kite.data import get_lambda_functions
from kite.data import get_rds_instances
from kite.data import get_security_groups
from kite.data import get_subnets
from kite.data import get_vpcs
from kite.helpers import get_account_ids_in_scope
from kite.helpers import get_prowler_output

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
    prowler_output = get_prowler_output()
    analysis = "Security Group Network Flow Analysis:\n\n"
    vpcs_by_account_and_region = defaultdict(dict)
    for account_id in accounts:
        for region in config.active_regions:
            vpcs_with_resources = _get_vpcs_with_resources(account_id, region)
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


def _is_rds_instance_in_subnet(rds_instance, subnet_id):
    subnets = rds_instance["DBSubnetGroup"]["Subnets"]
    return any(subnet["SubnetIdentifier"] == subnet_id for subnet in subnets)


def _is_eks_cluster_in_subnet(eks_cluster, subnet_id):
    subnet_ids = eks_cluster["resourcesVpcConfig"]["subnetIds"]
    return subnet_id in subnet_ids


def _is_ecs_service_in_subnet(ecs_service, subnet_id):
    subnet_ids = ecs_service["networkConfiguration"]["awsvpcConfiguration"]["subnets"]
    return subnet_id in subnet_ids


def _is_efs_in_subnet(efs, subnet_id):
    mount_targets = efs["MountTargets"]
    return any(mount_target["SubnetId"] == subnet_id for mount_target in mount_targets)


def _is_elbv2_in_subnet(elb, subnet_id):
    azs = elb["AvailabilityZones"]
    return any(az["SubnetId"] == subnet_id for az in azs)


def _get_resources_in_subnet(
    subnet_id,
    rds_instances,
    eks_clusters,
    ecs_clusters,
    ec2_instances,
    lambda_functions,
    efs_file_systems,
    elbv2_load_balancers,
):
    resources = {}
    rds_instances = [
        rds for rds in rds_instances if _is_rds_instance_in_subnet(rds, subnet_id)
    ]
    for rds in rds_instances:
        rds["Name"] = rds["DBInstanceIdentifier"]
        rds["SecurityGroupIds"] = [
            sg["VpcSecurityGroupId"] for sg in rds["VpcSecurityGroups"]
        ]
    if rds_instances:
        resources["RDS"] = rds_instances

    eks_clusters = [
        eks for eks in eks_clusters if _is_eks_cluster_in_subnet(eks, subnet_id)
    ]
    for eks in eks_clusters:
        eks["Name"] = eks["name"]
        vpc_config = eks["resourcesVpcConfig"]
        eks["SecurityGroupIds"] = vpc_config.get(
            "securityGroupIds", []
        ) + vpc_config.get("clusterSecurityGroupId", [])
    if eks_clusters:
        resources["EKS"] = eks_clusters

    ecs_services = [
        service
        for cluster in ecs_clusters
        for service in cluster["services"]
        if _is_ecs_service_in_subnet(service, subnet_id)
    ]
    for service in ecs_services:
        service["Name"] = service["serviceArn"]
        network_config = service.get("networkConfiguration", {})
        awsvpc_config = network_config.get("awsvpcConfiguration", {})
        service["SecurityGroupIds"] = awsvpc_config.get("securityGroups", [])
    if ecs_services:
        resources["ECS"] = ecs_services

    ec2_instances = [i for i in ec2_instances if i["SubnetId"] == subnet_id]
    for instance in ec2_instances:
        instance["Name"] = instance["InstanceId"]
        instance["SecurityGroupIds"] = [
            sg["GroupId"] for sg in instance.get("SecurityGroups", [])
        ]
    if ec2_instances:
        resources["EC2"] = ec2_instances

    functions = [
        func
        for func in lambda_functions
        if subnet_id in func.get("VpcConfig", {}).get("SubnetIds", [])
    ]
    for f in functions:
        f["Name"] = f["FunctionName"]
        vpc_config = f.get("VpcConfig", {})
        f["SecurityGroupIds"] = vpc_config.get("SecurityGroupIds", [])
    if functions:
        resources["Lambda"] = functions

    efs_file_systems = [
        efs for efs in efs_file_systems if _is_efs_in_subnet(efs, subnet_id)
    ]
    for efs in efs_file_systems:
        efs["Name"] = efs["Name"]
        mts = efs.get("MountTargets", [])
        sgs = []
        for mt in mts:
            sgs.extend(mt.get("SecurityGroups", []))
        efs["SecurityGroupIds"] = sgs
    if efs_file_systems:
        resources["EFS"] = efs_file_systems

    elbs = [lb for lb in elbv2_load_balancers if _is_elbv2_in_subnet(lb, subnet_id)]
    for elb in elbs:
        elb["Name"] = elb["LoadBalancerName"]
        elb["SecurityGroupIds"] = elb.get("SecurityGroups", [])
    if elbs:
        resources["ELBv2"] = elbs
    return resources


def _get_vpcs_with_resources(account_id: str, region: str):
    vpcs = get_vpcs(account_id, region)
    if not vpcs:
        return []

    subnets = get_subnets(account_id, region)
    rds_instances = get_rds_instances(account_id, region)
    eks_clusters = get_eks_clusters(account_id, region)
    ecs_clusters = get_ecs_clusters(account_id, region)
    ec2_instances = get_ec2_instances(account_id, region) or []
    lambda_functions = get_lambda_functions(account_id, region)
    efs_file_systems = get_efs_file_systems(account_id, region)
    elbv2_load_balancers = get_elbv2_load_balancers(account_id, region)
    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        vpc["Subnets"] = []
        vpc_subnets = [s for s in subnets if s["VpcId"] == vpc_id]
        for subnet in vpc_subnets:
            subnet_id = subnet["SubnetId"]
            resources = _get_resources_in_subnet(
                subnet_id,
                rds_instances,
                eks_clusters,
                ecs_clusters,
                ec2_instances,
                lambda_functions,
                efs_file_systems,
                elbv2_load_balancers,
            )
            if resources:
                subnet["Resources"] = resources
                vpc["Subnets"].append(subnet)
    return [vpc for vpc in vpcs if vpc["Subnets"]]


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
