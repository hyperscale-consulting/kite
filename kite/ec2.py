"""EC2 service module for Kite."""

import boto3


def get_running_instances(session, region: str) -> list[dict[str, object]]:
    """
    Get all non-terminated EC2 instances in a region.

    Args:
        session: The boto3 session to use
        region: The AWS region to check

    Returns:
        List of non-terminated EC2 instances
    """
    ec2_client = session.client("ec2", region_name=region)
    instances = []

    # Use paginator for describe_instances
    paginator = ec2_client.get_paginator("describe_instances")

    # Iterate through all pages
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                if instance.get("State", {}).get("Name") != "terminated":
                    instances.append(instance)

    return instances


def get_key_pairs(session: boto3.Session) -> list[dict[str, object]]:
    """
    Get all EC2 key pairs in the account.

    Args:
        session: boto3 session to use for the API call

    Returns:
        List of dictionaries containing key pair information
    """
    ec2 = session.client("ec2")
    response = ec2.describe_key_pairs()
    return response.get("KeyPairs", [])


def get_vpc_endpoints(session: boto3.Session, region: str) -> list[dict[str, object]]:
    """
    Get all VPC endpoints in the account.

    Args:
        session: boto3 session to use for the API call

    Returns:
        List of dictionaries containing VPC endpoint information
    """
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_vpc_endpoints")
    endpoints = []
    for page in paginator.paginate():
        endpoints.extend(page.get("VpcEndpoints", []))
    return endpoints


def get_flow_logs(session: boto3.Session, region: str) -> list[dict[str, object]]:
    """
    Get all flow logs in the account.
    """
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_flow_logs")
    flow_logs = []
    for page in paginator.paginate():
        flow_logs.extend(page.get("FlowLogs", []))
    return flow_logs


def get_vpcs(session: boto3.Session, region: str) -> list[dict[str, object]]:
    """
    Get all VPCs in the account.
    """
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_vpcs")
    vpcs = []
    for page in paginator.paginate():
        vpcs.extend(page.get("Vpcs", []))
    return vpcs


def get_subnets(session: boto3.Session, region: str) -> list[dict[str, object]]:
    """
    Get all subnets in the account.
    """
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_subnets")
    subnets = []
    for page in paginator.paginate():
        subnets.extend(page.get("Subnets", []))
    return subnets


def get_rtbs(session: boto3.Session, region: str) -> list[dict[str, object]]:
    """
    Get all route tables in the account.
    """
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_route_tables")
    rtbs = []
    for page in paginator.paginate():
        rtbs.extend(page.get("RouteTables", []))
    return rtbs


def get_nacls(session: boto3.Session, region: str) -> list[dict[str, object]]:
    """
    Get all network ACLs in the account.
    """
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_network_acls")
    nacls = []
    for page in paginator.paginate():
        nacls.extend(page.get("NetworkAcls", []))
    return nacls


def get_security_groups(session: boto3.Session, region: str) -> list[dict[str, object]]:
    """
    Get all security groups in the account.
    """
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_security_groups")
    security_groups = []
    for page in paginator.paginate():
        security_groups.extend(page.get("SecurityGroups", []))
    return security_groups


def get_vpc_peering_connections(
    session: boto3.Session, region: str
) -> list[dict[str, object]]:
    """
    Get all VPC peering connections in the account.
    """
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_vpc_peering_connections")
    vpc_peering_connections = []
    for page in paginator.paginate():
        vpc_peering_connections.extend(page.get("VpcPeeringConnections", []))
    return vpc_peering_connections
