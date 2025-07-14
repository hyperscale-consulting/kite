"""Manual check for controlling network flow with NACLs."""

from typing import Any

from kite.config import Config
from kite.data import get_ec2_instances
from kite.data import get_ecs_clusters
from kite.data import get_efs_file_systems
from kite.data import get_eks_clusters
from kite.data import get_elbv2_load_balancers
from kite.data import get_lambda_functions
from kite.data import get_nacls
from kite.data import get_rds_instances
from kite.data import get_subnets
from kite.data import get_vpcs
from kite.helpers import get_account_ids_in_scope
from kite.helpers import get_prowler_output
from kite.helpers import manual_check

CHECK_ID = "control-network-flow-with-nacls"
CHECK_NAME = "Control Network Flow with NACLs"


def _get_vpc_name(vpc: dict[str, Any]) -> str:
    tags = vpc.get("Tags", [])
    for tag in tags:
        if tag.get("Key") == "Name":
            return tag.get("Value", "")
    return ""


def _get_subnet_name(subnet: dict[str, Any]) -> str:
    tags = subnet.get("Tags", [])
    for tag in tags:
        if tag.get("Key") == "Name":
            return tag.get("Value", "")
    return ""


def _get_resources_in_subnet(
    subnet_id: str,
    rds_instances: list[dict[str, Any]],
    eks_clusters: list[dict[str, Any]],
    ecs_clusters: list[dict[str, Any]],
    ec2_instances: list[dict[str, Any]],
    lambda_functions: list[dict[str, Any]],
    efs_file_systems: list[dict[str, Any]],
    elbv2_load_balancers: list[dict[str, Any]],
) -> dict[str, list[str]]:
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
                resources["RDS"].append(rds.get("DBInstanceIdentifier", "Unknown"))
                break
    for eks in eks_clusters:
        vpc_config = eks.get("resourcesVpcConfig", {})
        subnet_ids = vpc_config.get("subnetIds", [])
        if subnet_id in subnet_ids:
            resources["EKS"].append(eks.get("name", "Unknown"))
    for ecs in ecs_clusters:
        services = ecs.get("services", [])
        for service in services:
            network_config = service.get("networkConfiguration", {})
            awsvpc_config = network_config.get("awsvpcConfiguration", {})
            subnets = awsvpc_config.get("subnets", [])
            if subnet_id in subnets:
                cluster_name = ecs.get("clusterName", "Unknown")
                service_name = service.get("serviceName", "Unknown")
                resources["ECS"].append(f"{cluster_name}/{service_name}")
    for ec2 in ec2_instances:
        if ec2.get("SubnetId") == subnet_id:
            resources["EC2"].append(ec2.get("InstanceId", "Unknown"))
    for lambda_func in lambda_functions:
        vpc_config = lambda_func.get("VpcConfig", {})
        subnet_ids = vpc_config.get("SubnetIds", [])
        if subnet_id in subnet_ids:
            resources["Lambda"].append(lambda_func.get("FunctionName", "Unknown"))
    for efs in efs_file_systems:
        mount_targets = efs.get("MountTargets", [])
        for mount_target in mount_targets:
            if mount_target.get("SubnetId") == subnet_id:
                resources["EFS"].append(
                    efs.get("Name", efs.get("FileSystemId", "Unknown"))
                )
                break
    for lb in elbv2_load_balancers:
        for az in lb.get("AvailabilityZones", []):
            if az.get("SubnetId") == subnet_id:
                resources["ELBv2"].append(
                    lb.get("LoadBalancerName", lb.get("LoadBalancerArn", "Unknown"))
                )
                break
    return resources


def _summarize_nacl_rules(nacl: dict[str, Any]) -> dict[str, list[str]]:
    """Summarize NACL rules for easy display."""
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


def _get_nacl_for_subnet(subnet_id: str, nacls: list[dict[str, Any]]) -> dict[str, Any]:
    for nacl in nacls:
        for assoc in nacl.get("Associations", []):
            if assoc.get("SubnetId") == subnet_id:
                return nacl
    return None


def _analyze_nacls() -> str:
    accounts = get_account_ids_in_scope()
    config = Config.get()
    prowler_checks = [
        "ec2_networkacl_allow_ingress_tcp_port_22",
        "ec2_networkacl_allow_ingress_tcp_port_3389",
        "ec2_networkacl_allow_ingress_any_port",
    ]
    prowler_output = get_prowler_output()
    analysis = "NACL Network Flow Analysis:\n\n"
    for account_id in accounts:
        account_has_resources = False
        account_analysis = f"Account: {account_id}\n" + "=" * 50 + "\n"
        for region in config.active_regions:
            region_has_resources = False
            region_analysis = f"\nRegion: {region}\n" + "-" * 30 + "\n"
            vpcs = get_vpcs(account_id, region)
            subnets = get_subnets(account_id, region)
            nacls = get_nacls(account_id, region)
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
                            vpc_analysis += (
                                f"    {resource_type}: {', '.join(resource_list)}\n"
                            )
                    nacl = _get_nacl_for_subnet(subnet_id, nacls)
                    if nacl:
                        nacl_summary = _summarize_nacl_rules(nacl)
                        nacl_id = nacl.get("NetworkAclId")
                        vpc_analysis += f"    NACL ({nacl_id}) Rules (Ingress):\n"
                        for rule in nacl_summary["ingress"]:
                            vpc_analysis += f"      {rule}\n"
                        vpc_analysis += f"    NACL ({nacl_id}) Rules (Egress):\n"
                        for rule in nacl_summary["egress"]:
                            vpc_analysis += f"      {rule}\n"
                        # Print prowler warnings for this NACL
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
                                vpc_analysis += f"      {warning}\n"
                    else:
                        vpc_analysis += "    No NACL associated with this subnet.\n"
                if region_has_resources:
                    region_analysis += vpc_analysis
            if region_has_resources:
                account_analysis += region_analysis
        if account_has_resources:
            analysis += account_analysis
    return analysis


def check_control_network_flow_with_nacls() -> dict[str, Any]:
    """
    Manual check to confirm whether NACLs are used to restrict ingress and egress traffic
    to only the flows necessary for each workload at each network layer. Prints a summary
    of VPCs, subnets, resources, and NACL rules for each subnet.
    """
    nacl_analysis = _analyze_nacls()
    message = (
        "This check helps you confirm whether Network Access Control Lists (NACLs) are used "
        "to restrict ingress and egress traffic to only the flows necessary for each "
        "workload at each network layer.\n\n"
        "Below is a summary of each VPC and subnet with resources, including a summary of "
        "the NACL rules applied to each subnet.\n\n"
        f"{nacl_analysis}"
    )
    prompt = (
        "Are NACLs used to restrict ingress and egress traffic to only the flows necessary "
        "for each workload at each network layer?"
    )
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "NACLs are used to restrict ingress and egress traffic to only the "
            "flows necessary for each workload at each network layer."
        ),
        fail_message=(
            "NACLs should be used to restrict ingress and egress traffic to only "
            "the flows necessary for each workload at each network layer."
        ),
        default=True,
    )
    return result


check_control_network_flow_with_nacls._CHECK_ID = CHECK_ID
check_control_network_flow_with_nacls._CHECK_NAME = CHECK_NAME
