"""Manual check for controlling network flows with Route Tables."""

from typing import Dict, Any, List
from kite.data import (
    get_vpcs,
    get_subnets,
    get_rtbs,
    get_rds_instances,
    get_eks_clusters,
    get_ecs_clusters,
    get_ec2_instances,
    get_lambda_functions,
    get_efs_file_systems,
    get_elbv2_load_balancers,
)
from kite.helpers import get_account_ids_in_scope, manual_check
from kite.config import Config

CHECK_ID = "control-network-flows-with-route-tables"
CHECK_NAME = "Control Network Flows with Route Tables"


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


def _get_resources_in_subnet(
    subnet_id: str,
    rds_instances: List[Dict[str, Any]],
    eks_clusters: List[Dict[str, Any]],
    ecs_clusters: List[Dict[str, Any]],
    ec2_instances: List[Dict[str, Any]],
    lambda_functions: List[Dict[str, Any]],
    efs_file_systems: List[Dict[str, Any]],
    elbv2_load_balancers: List[Dict[str, Any]],
) -> Dict[str, List[str]]:
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


def _summarize_route_table(rtb: Dict[str, Any]) -> List[str]:
    summary = []
    rtb_id = rtb.get("RouteTableId", "Unknown")
    summary.append(f"Route Table: {rtb_id}")
    for route in rtb.get("Routes", []):
        destination = (
            route.get("DestinationCidrBlock")
            or route.get("DestinationIpv6CidrBlock")
            or route.get("DestinationPrefixListId")
            or "?"
        )
        target = (
            route.get("GatewayId")
            or route.get("NatGatewayId")
            or route.get("TransitGatewayId")
            or route.get("VpcPeeringConnectionId")
            or route.get("InstanceId")
            or route.get("NetworkInterfaceId")
            or route.get("EgressOnlyInternetGatewayId")
            or "?"
        )
        summary.append(f"  {destination} -> {target}")
    return summary


def _get_route_tables_for_subnet(
    subnet_id: str, rtbs: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    associated = []
    for rtb in rtbs:
        associations = rtb.get("Associations", [])
        for assoc in associations:
            if (
                assoc.get("SubnetId") == subnet_id
                and assoc.get("AssociationState", {}).get("State") == "associated"
            ):
                associated.append(rtb)
    return associated


def _analyze_route_tables() -> str:
    accounts = get_account_ids_in_scope()
    config = Config.get()
    analysis = "Route Table Network Flow Analysis:\n\n"
    for account_id in accounts:
        account_has_resources = False
        account_analysis = f"Account: {account_id}\n" + "=" * 50 + "\n"
        for region in config.active_regions:
            region_has_resources = False
            region_analysis = f"\nRegion: {region}\n" + "-" * 30 + "\n"
            vpcs = get_vpcs(account_id, region)
            subnets = get_subnets(account_id, region)
            rtbs = get_rtbs(account_id, region)
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
                    # Route table summary
                    subnet_rtbs = _get_route_tables_for_subnet(subnet_id, rtbs)
                    if subnet_rtbs:
                        for rtb in subnet_rtbs:
                            for line in _summarize_route_table(rtb):
                                vpc_analysis += f"      {line}\n"
                    else:
                        vpc_analysis += (
                            "    No route table associated with this subnet.\n"
                        )
                if region_has_resources:
                    region_analysis += vpc_analysis
            if region_has_resources:
                account_analysis += region_analysis
        if account_has_resources:
            analysis += account_analysis
    return analysis


def check_control_network_flows_with_route_tables() -> Dict[str, Any]:
    """
    Manual check to confirm whether route tables are used to restrict network traffic flows
    to only the flows necessary for each workload. Prints a summary of VPCs, subnets, resources,
    and route tables for each subnet.
    """
    rtb_analysis = _analyze_route_tables()
    message = (
        "This check helps you confirm whether route tables are used to restrict network traffic "
        "flows to only the flows necessary for each workload.\n\n"
        "Below is a summary of each VPC and subnet with resources, including a summary of the "
        "route tables associated with each subnet.\n\n"
        f"{rtb_analysis}"
    )
    prompt = (
        "Are route tables used to restrict network traffic flows to only the flows necessary "
        "for each workload?"
    )
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Route Tables are used to restrict network traffic flows to only the flows necessary "
            "for each workload."
        ),
        fail_message=(
            "Route Tables should be used to restrict network traffic flows to only the flows necessary "
            "for each workload."
        ),
        default=True,
    )
    return result


check_control_network_flows_with_route_tables._CHECK_ID = CHECK_ID
check_control_network_flows_with_route_tables._CHECK_NAME = CHECK_NAME
