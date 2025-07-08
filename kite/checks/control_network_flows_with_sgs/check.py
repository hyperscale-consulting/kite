"""Manual check for controlling network flows with Security Groups."""

from typing import Dict, Any, List
from kite.data import (
    get_vpcs,
    get_subnets,
    get_security_groups,
    get_rds_instances,
    get_eks_clusters,
    get_ecs_clusters,
    get_ec2_instances,
    get_lambda_functions,
    get_efs_file_systems,
    get_elbv2_load_balancers,
)
from kite.helpers import get_account_ids_in_scope, manual_check, get_prowler_output
from kite.config import Config

CHECK_ID = "control-network-flows-with-sgs"
CHECK_NAME = "Control Network Flows with Security Groups"


def _get_vpc_name(vpc: Dict[str, Any]) -> str:
    tags = vpc.get("Tags", [])
    for tag in tags:
        if tag.get("Key") == "Name":
            return tag.get("Value", "")
    return ""


def _get_subnet_name(subnet: Dict[str, Any]) -> str:
    tags = subnet.get("Tags", [])
    for tag in tags:
        if tag.get("Key") == "Name":
            return tag.get("Value", "")
    return ""


def _get_security_group_name(sg: Dict[str, Any]) -> str:
    tags = sg.get("Tags", [])
    for tag in tags:
        if tag.get("Key") == "Name":
            return tag.get("Value", "")
    return sg.get("GroupName", "")


def _get_resources_in_subnet(
    subnet_id: str,
    rds_instances: List[Dict[str, Any]],
    eks_clusters: List[Dict[str, Any]],
    ecs_clusters: List[Dict[str, Any]],
    ec2_instances: List[Dict[str, Any]],
    lambda_functions: List[Dict[str, Any]],
    efs_file_systems: List[Dict[str, Any]],
    elbv2_load_balancers: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    resources = {
        "RDS": [],
        "EKS": [],
        "ECS": [],
        "EC2": [],
        "Lambda": [],
        "EFS": [],
        "ELBv2": [],
    }
    for rds in rds_instances:
        db_subnet_group = rds.get("DBSubnetGroup", {})
        subnets = db_subnet_group.get("Subnets", [])
        for subnet in subnets:
            if subnet.get("SubnetIdentifier") == subnet_id:
                resources["RDS"].append(rds)
                break
    for eks in eks_clusters:
        vpc_config = eks.get("resourcesVpcConfig", {})
        subnet_ids = vpc_config.get("subnetIds", [])
        if subnet_id in subnet_ids:
            resources["EKS"].append(eks)
    for ecs in ecs_clusters:
        services = ecs.get("services", [])
        for service in services:
            network_config = service.get("networkConfiguration", {})
            awsvpc_config = network_config.get("awsvpcConfiguration", {})
            subnets = awsvpc_config.get("subnets", [])
            service["clusterName"] = ecs.get("clusterName", "Unknown")
            if subnet_id in subnets:
                resources["ECS"].append(service)
    for ec2 in ec2_instances:
        if ec2.get("SubnetId") == subnet_id:
            resources["EC2"].append(ec2)
    for lambda_func in lambda_functions:
        vpc_config = lambda_func.get("VpcConfig", {})
        subnet_ids = vpc_config.get("SubnetIds", [])
        if subnet_id in subnet_ids:
            resources["Lambda"].append(lambda_func)
    for efs in efs_file_systems:
        mount_targets = efs.get("MountTargets", [])
        for mount_target in mount_targets:
            if mount_target.get("SubnetId") == subnet_id:
                resources["EFS"].append(efs)
                break
    for lb in elbv2_load_balancers:
        for az in lb.get("AvailabilityZones", []):
            if az.get("SubnetId") == subnet_id:
                resources["ELBv2"].append(lb)
                break
    return resources


def _summarize_security_group_rules(sg: Dict[str, Any]) -> Dict[str, List[str]]:
    """Summarize security group rules for easy display."""
    summary = {"ingress": [], "egress": []}

    # Process ingress rules
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

        # Process IP ranges
        ip_ranges = rule.get("IpRanges", [])
        for ip_range in ip_ranges:
            cidr = ip_range.get("CidrIp", "?")
            summary["ingress"].append(
                f"ALLOW {proto_str} {port_str} from {cidr}"
            )

        # Process security group references
        user_id_group_pairs = rule.get("UserIdGroupPairs", [])
        for group_pair in user_id_group_pairs:
            group_id = group_pair.get("GroupId", "?")
            summary["ingress"].append(
                f"ALLOW {proto_str} {port_str} from SG {group_id}"
            )

    # Process egress rules
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

        # Process IP ranges
        ip_ranges = rule.get("IpRanges", [])
        for ip_range in ip_ranges:
            cidr = ip_range.get("CidrIp", "?")
            summary["egress"].append(
                f"ALLOW {proto_str} {port_str} to {cidr}"
            )

        # Process security group references
        user_id_group_pairs = rule.get("UserIdGroupPairs", [])
        for group_pair in user_id_group_pairs:
            group_id = group_pair.get("GroupId", "?")
            summary["egress"].append(
                f"ALLOW {proto_str} {port_str} to SG {group_id}"
            )

    return summary


def _get_security_groups_for_resource(
    resource: Dict[str, Any], resource_type: str, security_groups: List[Dict[str, Any]]
) -> List[str]:
    """Get security group IDs associated with a resource."""
    sg_ids = []

    if resource_type == "EC2":
        for sg in resource.get("SecurityGroups", []):
            sg_ids.append(sg.get("GroupId"))
    elif resource_type == "RDS":
        for sg in resource.get("VpcSecurityGroups", []):
            sg_ids.append(sg.get("VpcSecurityGroupId"))
    elif resource_type == "ECS":
        network_config = resource.get("networkConfiguration", {})
        awsvpc_config = network_config.get("awsvpcConfiguration", {})
        sg_ids.extend(awsvpc_config.get("securityGroups", []))
    elif resource_type == "Lambda":
        vpc_config = resource.get("VpcConfig", {})
        sg_ids.extend(vpc_config.get("SecurityGroupIds", []))
    elif resource_type == "EFS":
        mount_targets = resource.get("MountTargets", [])
        for mount_target in mount_targets:
            sg_ids.extend(mount_target.get("SecurityGroups", []))
    elif resource_type == "EKS":
        vpc_config = resource.get("resourcesVpcConfig", {})
        sg_ids.extend(vpc_config.get("securityGroupIds", []))
        cluster_sg = vpc_config.get("clusterSecurityGroupId")
        if cluster_sg:
            sg_ids.append(cluster_sg)
    elif resource_type == "ELBv2":
        sg_ids.extend(resource.get("SecurityGroups", []))

    return sg_ids


def _analyze_security_groups() -> str:
    accounts = get_account_ids_in_scope()
    config = Config.get()
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
    prowler_output = get_prowler_output()
    analysis = "Security Group Network Flow Analysis:\n\n"

    for account_id in accounts:
        account_has_resources = False
        account_analysis = f"Account: {account_id}\n" + "=" * 50 + "\n"

        for region in config.active_regions:
            region_has_resources = False
            region_analysis = f"\nRegion: {region}\n" + "-" * 30 + "\n"

            vpcs = get_vpcs(account_id, region)
            subnets = get_subnets(account_id, region)
            security_groups = get_security_groups(account_id, region)
            rds_instances = get_rds_instances(account_id, region)
            eks_clusters = get_eks_clusters(account_id, region)
            ecs_clusters = get_ecs_clusters(account_id, region)
            ec2_instances = get_ec2_instances(account_id, region) or []
            lambda_functions = get_lambda_functions(account_id, region)
            efs_file_systems = get_efs_file_systems(account_id, region)
            elbv2_load_balancers = get_elbv2_load_balancers(account_id, region)

            if not vpcs:
                continue

            for vpc in vpcs:
                vpc_id = vpc.get("VpcId", "Unknown")
                vpc_name = _get_vpc_name(vpc)
                vpc_cidr = vpc.get("CidrBlock", "Unknown")
                vpc_analysis = f"\nVPC: {vpc_id}"
                if vpc_name:
                    vpc_analysis += f" (Name: {vpc_name})"
                vpc_analysis += f" - CIDR: {vpc_cidr}\n"

                vpc_subnets = [s for s in subnets if s.get("VpcId") == vpc_id]

                for subnet in vpc_subnets:
                    subnet_id = subnet.get("SubnetId", "Unknown")
                    subnet_name = _get_subnet_name(subnet)
                    subnet_cidr = subnet.get("CidrBlock", "Unknown")
                    availability_zone = subnet.get("AvailabilityZone", "Unknown")

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

                    if not any(resources.values()):
                        continue

                    account_has_resources = True
                    region_has_resources = True

                    vpc_analysis += f"  Subnet: {subnet_id}"
                    if subnet_name:
                        vpc_analysis += f" (Name: {subnet_name})"
                    vpc_analysis += (
                        f" - CIDR: {subnet_cidr} - AZ: {availability_zone}\n"
                    )

                    for resource_type, resource_list in resources.items():
                        if resource_list:
                            vpc_analysis += f"    {resource_type}:\n"
                            for resource in resource_list:
                                if resource_type == "RDS":
                                    resource_name = resource.get("DBInstanceIdentifier", "Unknown")
                                elif resource_type == "EKS":
                                    resource_name = resource.get("name", "Unknown")
                                elif resource_type == "ECS":
                                    cluster_name = resource.get("clusterName", "Unknown")
                                    service_name = resource.get("serviceName", "Unknown")
                                    resource_name = f"{cluster_name}/{service_name}"
                                elif resource_type == "EC2":
                                    resource_name = resource.get("InstanceId", "Unknown")
                                elif resource_type == "Lambda":
                                    resource_name = resource.get("FunctionName", "Unknown")
                                elif resource_type == "EFS":
                                    resource_name = resource.get("Name", resource.get("FileSystemId", "Unknown"))
                                elif resource_type == "ELBv2":
                                    resource_name = resource.get("LoadBalancerName", resource.get("LoadBalancerArn", "Unknown"))
                                else:
                                    resource_name = "Unknown"

                                vpc_analysis += f"      {resource_name}:\n"

                                # Get security groups for this resource
                                sg_ids = _get_security_groups_for_resource(
                                    resource, resource_type, security_groups
                                )

                                if sg_ids:
                                    for sg_id in sg_ids:
                                        # Find the security group details
                                        sg_details = None
                                        for sg in security_groups:
                                            if sg.get("GroupId") == sg_id:
                                                sg_details = sg
                                                break

                                        if sg_details:
                                            sg_name = _get_security_group_name(sg_details)
                                            vpc_analysis += f"        SG {sg_id}"
                                            if sg_name:
                                                vpc_analysis += f" ({sg_name})"
                                            vpc_analysis += ":\n"

                                            # Show security group rules
                                            sg_summary = _summarize_security_group_rules(sg_details)
                                            if sg_summary["ingress"]:
                                                vpc_analysis += "          Ingress:\n"
                                                for rule in sg_summary["ingress"]:
                                                    vpc_analysis += f"            {rule}\n"
                                            if sg_summary["egress"]:
                                                vpc_analysis += "          Egress:\n"
                                                for rule in sg_summary["egress"]:
                                                    vpc_analysis += f"            {rule}\n"

                                            # Show prowler warnings for this security group
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
                                                    vpc_analysis += f"          {warning}\n"
                                        else:
                                            vpc_analysis += f"        SG {sg_id} (not found)\n"
                                else:
                                    vpc_analysis += "        No security groups found\n"

                if region_has_resources:
                    region_analysis += vpc_analysis
            if region_has_resources:
                account_analysis += region_analysis
        if account_has_resources:
            analysis += account_analysis

    return analysis


def check_control_network_flows_with_sgs() -> Dict[str, Any]:
    """
    Manual check to confirm whether Security Groups are used to restrict ingress and egress traffic
    to only the flows necessary for each workload at each network layer. Prints a summary
    of VPCs, subnets, resources, and security group rules for each resource.
    """
    sg_analysis = _analyze_security_groups()
    message = (
        "This check helps you confirm whether Security Groups are used to restrict "
        "ingress and egress traffic to only the flows necessary for each workload "
        "at each network layer.\n\n"
        "Below is a summary of each VPC and subnet with resources, including a "
        "summary of the security group rules applied to each resource.\n\n"
        f"{sg_analysis}"
    )
    prompt = (
        "Are Security Groups used to restrict ingress and egress traffic to only "
        "the flows necessary for each workload at each network layer?"
    )
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Security Groups are used to restrict ingress and egress traffic to "
            "only the flows necessary for each workload at each network layer."
        ),
        fail_message=(
            "Security Groups should be used to restrict ingress and egress traffic "
            "to only the flows necessary for each workload at each network layer."
        ),
        default=True,
    )
    return result


check_control_network_flows_with_sgs._CHECK_ID = CHECK_ID
check_control_network_flows_with_sgs._CHECK_NAME = CHECK_NAME
