"""Manual check for creating network layers based on workload components."""

from typing import Any

from kite.config import Config
from kite.data import get_ec2_instances
from kite.data import get_ecs_clusters
from kite.data import get_efs_file_systems
from kite.data import get_eks_clusters
from kite.data import get_elbv2_load_balancers
from kite.data import get_lambda_functions
from kite.data import get_rds_instances
from kite.data import get_rtbs
from kite.data import get_subnets
from kite.data import get_vpcs
from kite.helpers import get_account_ids_in_scope
from kite.helpers import manual_check

CHECK_ID = "create-network-layers"
CHECK_NAME = "Create Network Layers"


def _get_vpc_name(vpc: dict[str, Any]) -> str:
    """Extract VPC name from tags."""
    tags = vpc.get("Tags", [])
    for tag in tags:
        if tag.get("Key") == "Name":
            return tag.get("Value", "")
    return ""


def _get_subnet_name(subnet: dict[str, Any]) -> str:
    """Extract subnet name from tags."""
    tags = subnet.get("Tags", [])
    for tag in tags:
        if tag.get("Key") == "Name":
            return tag.get("Value", "")
    return ""


def _is_subnet_private(subnet_id: str, route_tables: list[dict[str, Any]]) -> bool:
    """
    Determine if a subnet is private by checking if it has routes to internet gateway.

    A subnet is private if it has no direct routes to an internet gateway.
    This can be determined from looking for a route table that has an association
    (Associations attribute) with a SubnetId attribute for that subnet, and
    AssociationState.State = 'associated', and there are no routes (Route attribute)
    with a GatewayId references an internet gateway (a string starting 'igw-'),
    and a DestinationCidrBlock = "0.0.0.0/0"
    """
    for rtb in route_tables:
        # Check if this route table is associated with the subnet
        associations = rtb.get("Associations", [])
        subnet_associated = False

        for assoc in associations:
            if (
                assoc.get("SubnetId") == subnet_id
                and assoc.get("AssociationState", {}).get("State") == "associated"
            ):
                subnet_associated = True
                break

        if not subnet_associated:
            continue

        # Check if this route table has a route to internet gateway
        routes = rtb.get("Routes", [])
        for route in routes:
            gateway_id = route.get("GatewayId", "")
            destination = route.get("DestinationCidrBlock", "")

            if gateway_id.startswith("igw-") and destination == "0.0.0.0/0":
                return False  # Subnet has internet access, so it's public

    return True  # No internet gateway route found, so it's private


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
    """Get all resources in a specific subnet."""
    resources = {
        "RDS": [],
        "EKS": [],
        "ECS": [],
        "EC2": [],
        "Lambda": [],
        "EFS": [],
        "ELBv2": [],
    }

    # Check RDS instances
    for rds in rds_instances:
        db_subnet_group = rds.get("DBSubnetGroup", {})
        subnets = db_subnet_group.get("Subnets", [])
        for subnet in subnets:
            if subnet.get("SubnetIdentifier") == subnet_id:
                resources["RDS"].append(rds.get("DBInstanceIdentifier", "Unknown"))
                break

    # Check EKS clusters
    for eks in eks_clusters:
        vpc_config = eks.get("resourcesVpcConfig", {})
        subnet_ids = vpc_config.get("subnetIds", [])
        if subnet_id in subnet_ids:
            resources["EKS"].append(eks.get("name", "Unknown"))

    # Check ECS clusters and services
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

    # Check EC2 instances
    for ec2 in ec2_instances:
        if ec2.get("SubnetId") == subnet_id:
            resources["EC2"].append(ec2.get("InstanceId", "Unknown"))

    # Check Lambda functions
    for lambda_func in lambda_functions:
        vpc_config = lambda_func.get("VpcConfig", {})
        subnet_ids = vpc_config.get("SubnetIds", [])
        if subnet_id in subnet_ids:
            resources["Lambda"].append(lambda_func.get("FunctionName", "Unknown"))

    # Check EFS file systems
    for efs in efs_file_systems:
        mount_targets = efs.get("MountTargets", [])
        for mount_target in mount_targets:
            if mount_target.get("SubnetId") == subnet_id:
                resources["EFS"].append(
                    efs.get("Name", efs.get("FileSystemId", "Unknown"))
                )
                break

    # Check ELBv2 load balancers
    for lb in elbv2_load_balancers:
        for az in lb.get("AvailabilityZones", []):
            if az.get("SubnetId") == subnet_id:
                resources["ELBv2"].append(
                    lb.get("LoadBalancerName", lb.get("LoadBalancerArn", "Unknown"))
                )
                break

    return resources


def _analyze_network_topology() -> str:
    """Analyze the network topology across all accounts and regions."""
    accounts = get_account_ids_in_scope()
    config = Config.get()
    analysis = "Network Topology Analysis:\n\n"
    public_warnings = []
    lambdas_without_vpc = []
    for account_id in accounts:
        account_has_resources = False
        account_analysis = f"Account: {account_id}\n" + "=" * 50 + "\n"
        for region in config.active_regions:
            region_has_resources = False
            region_analysis = f"\nRegion: {region}\n" + "-" * 30 + "\n"
            vpcs = get_vpcs(account_id, region)
            route_tables = get_rtbs(account_id, region)
            subnets = get_subnets(account_id, region)
            rds_instances = get_rds_instances(account_id, region)
            eks_clusters = get_eks_clusters(account_id, region)
            ecs_clusters = get_ecs_clusters(account_id, region)
            ec2_instances = get_ec2_instances(account_id, region) or []
            lambda_functions = get_lambda_functions(account_id, region)
            efs_file_systems = get_efs_file_systems(account_id, region)
            elbv2_load_balancers = get_elbv2_load_balancers(account_id, region)
            # Collect Lambdas without VPC config for this region
            for lambda_func in lambda_functions:
                if "VpcConfig" not in lambda_func or not lambda_func.get("VpcConfig"):
                    lambdas_without_vpc.append(
                        f"{lambda_func.get('FunctionName', 'Unknown')} (account: {account_id}, region: {region})"
                    )
            if not vpcs:
                continue
            for vpc in vpcs:
                vpc_id = vpc.get("VpcId", "Unknown")
                vpc_name = _get_vpc_name(vpc)
                vpc_cidr = vpc.get("CidrBlock", "Unknown")
                vpc_has_resources = False
                vpc_analysis = f"\nVPC: {vpc_id}"
                if vpc_name:
                    vpc_analysis += f" (Name: {vpc_name})"
                vpc_analysis += f" - CIDR: {vpc_cidr}\n"
                vpc_subnets = [s for s in subnets if s.get("VpcId") == vpc_id]
                if not vpc_subnets:
                    continue
                for subnet in vpc_subnets:
                    subnet_id = subnet.get("SubnetId", "Unknown")
                    subnet_name = _get_subnet_name(subnet)
                    subnet_cidr = subnet.get("CidrBlock", "Unknown")
                    availability_zone = subnet.get("AvailabilityZone", "Unknown")
                    is_private = _is_subnet_private(subnet_id, route_tables)
                    subnet_type = "Private" if is_private else "Public"
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
                    vpc_has_resources = True
                    region_has_resources = True
                    account_has_resources = True
                    vpc_analysis += f"  Subnet: {subnet_id}"
                    if subnet_name:
                        vpc_analysis += f" (Name: {subnet_name})"
                    vpc_analysis += (
                        f" - {subnet_type} - CIDR: {subnet_cidr} - "
                        f"AZ: {availability_zone}\n"
                    )
                    has_resources = False
                    for resource_type, resource_list in resources.items():
                        if resource_list:
                            has_resources = True
                            vpc_analysis += (
                                f"    {resource_type}: {', '.join(resource_list)}\n"
                            )
                            if subnet_type == "Public" and resource_type in [
                                "RDS",
                                "EFS",
                                "EKS",
                                "ECS",
                                "EC2",
                                "Lambda",
                            ]:
                                for res in resource_list:
                                    public_warnings.append(
                                        f"{resource_type} {res} in public subnet {subnet_id} "
                                        f"(account: {account_id}, region: {region}, vpc: {vpc_id})"
                                    )
                    if not has_resources:
                        vpc_analysis += "    No resources found in this subnet.\n"
                if vpc_has_resources:
                    region_analysis += vpc_analysis
            if region_has_resources:
                account_analysis += region_analysis
        if account_has_resources:
            analysis += account_analysis
    if lambdas_without_vpc:
        analysis += (
            "\n⚠️ The following Lambda functions are not deployed in a VPC "
            "(should be deployed in a VPC unless there's a good reason):\n"
        )
        for lambda_name in lambdas_without_vpc:
            analysis += f"  - {lambda_name}\n"
    if public_warnings:
        analysis += (
            "\n⚠️ The following resources are running in public subnets "
            "(should be private unless there's a good reason):\n"
        )
        for warning in public_warnings:
            analysis += f"  - {warning}\n"
    return analysis


def check_create_network_layers() -> dict[str, Any]:
    """
    Check if network topology is segmented into different layers based on logical
    groupings of workload components according to their data sensitivity and access requirements.

    This check analyzes the network topology and provides detailed information about:
    - Each VPC in each account and region
    - Each subnet and whether it's public or private
    - Resources in each subnet
    - Lambda functions that should be deployed in VPC

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    # Analyze network topology first
    network_analysis = _analyze_network_topology()

    # Define the message and prompts with the network analysis included
    message = (
        "This check analyzes your network topology to help you understand if your "
        "network is properly segmented into different layers based on logical "
        "groupings of your workload components according to their data sensitivity "
        "and access requirements.\n\n"
        "The analysis below shows:\n"
        "- Each VPC in each account and region\n"
        "- Each subnet and whether it's public or private\n"
        "- Resources deployed in each subnet\n"
        "- Lambda functions that should be deployed in VPC\n\n"
        "Consider the following factors:\n"
        "- Are your resources separated into different layers according to their "
        "data sensitivity and access requirements?\n"
        "- Are public-facing resources isolated from private resources?\n"
        "- Are data and application tiers separated?\n\n"
        f"{network_analysis}"
    )

    prompt = (
        "Is your network topology segmented into different layers based on "
        "logical groupings of your workload components according to their "
        "data sensitivity and access requirements?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Your network topology is properly segmented into different layers "
            "based on logical groupings of workload components according to their "
            "data sensitivity and access requirements."
        ),
        fail_message=(
            "Your network topology should be segmented into different layers "
            "based on logical groupings of workload components according to their "
            "data sensitivity and access requirements."
        ),
        default=True,
    )

    return result


check_create_network_layers._CHECK_ID = CHECK_ID
check_create_network_layers._CHECK_NAME = CHECK_NAME
